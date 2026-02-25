"""
NHI Shield - Credential Vault v2.0
Full versioning: store, retrieve, rotate, rollback, audit per credential.
AES-256-GCM encryption with per-record salt and version chain.
"""

import os, json, logging, hashlib, secrets, base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)
ITERATIONS = 480_000

@dataclass
class CredentialVersion:
    version: int
    identity_id: str
    credential_id: Optional[str]
    encrypted_value: str
    salt: str
    hash_fingerprint: str
    created_at: datetime
    created_by: Optional[str]
    rotation_reason: Optional[str]
    is_active: bool = True

    def to_dict(self):
        return {
            'version': self.version, 'identity_id': self.identity_id,
            'credential_id': self.credential_id, 'hash_fingerprint': self.hash_fingerprint,
            'created_at': self.created_at.isoformat(), 'created_by': self.created_by,
            'rotation_reason': self.rotation_reason, 'is_active': self.is_active,
        }

class CredentialVault:
    def __init__(self, master_key: Optional[str] = None, pg_pool=None):
        raw = master_key or os.getenv('ENCRYPTION_KEY', '')
        if not raw or len(raw) < 32:
            raise ValueError('ENCRYPTION_KEY must be >= 32 characters')
        self._master = raw[:32].encode()
        self.pg_pool = pg_pool

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
        return kdf.derive(self._master)

    def _encrypt(self, plaintext: str):
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(12)
        ct_tag = AESGCM(self._derive_key(salt)).encrypt(iv, plaintext.encode(), None)
        return base64.b64encode(iv + ct_tag).decode(), salt.hex()

    def _decrypt(self, encrypted_b64: str, salt_hex: str) -> str:
        raw = base64.b64decode(encrypted_b64)
        return AESGCM(self._derive_key(bytes.fromhex(salt_hex))).decrypt(raw[:12], raw[12:], None).decode()

    def _fingerprint(self, plaintext: str) -> str:
        return hashlib.sha256(plaintext.encode()).hexdigest()

    async def store(self, identity_id: str, plaintext: str, credential_id=None,
                    created_by=None, rotation_reason=None) -> CredentialVersion:
        encrypted, salt = self._encrypt(plaintext)
        fp = self._fingerprint(plaintext)
        async with self.pg_pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "UPDATE credential_vault SET is_active=false WHERE identity_id=$1 AND is_active=true",
                    identity_id)
                row = await conn.fetchrow(
                    "SELECT COALESCE(MAX(version),0)+1 AS nv FROM credential_vault WHERE identity_id=$1",
                    identity_id)
                nv = row['nv']
                await conn.execute("""
                    INSERT INTO credential_vault
                    (identity_id,version,credential_id,encrypted_value,salt,hash_fingerprint,
                     created_by,rotation_reason,is_active,created_at)
                    VALUES($1,$2,$3,$4,$5,$6,$7,$8,true,NOW())
                """, identity_id, nv, credential_id, encrypted, salt, fp, created_by, rotation_reason)
                try:
                    await conn.execute(
                        "INSERT INTO audit_logs(identity_id,action,description,metadata,created_at) VALUES($1,'VAULT_STORE',$2,$3,NOW())",
                        identity_id, f'Credential v{nv} stored', json.dumps({'version': nv, 'reason': rotation_reason}))
                except Exception:
                    pass
        logger.info(f"Stored v{nv} for {identity_id}")
        return CredentialVersion(version=nv, identity_id=identity_id, credential_id=credential_id,
                                 encrypted_value=encrypted, salt=salt, hash_fingerprint=fp,
                                 created_at=datetime.now(timezone.utc), created_by=created_by,
                                 rotation_reason=rotation_reason)

    async def retrieve(self, identity_id: str, version: Optional[int] = None) -> Optional[str]:
        async with self.pg_pool.acquire() as conn:
            if version:
                row = await conn.fetchrow(
                    "SELECT encrypted_value,salt FROM credential_vault WHERE identity_id=$1 AND version=$2",
                    identity_id, version)
            else:
                row = await conn.fetchrow(
                    "SELECT encrypted_value,salt FROM credential_vault WHERE identity_id=$1 AND is_active=true LIMIT 1",
                    identity_id)
        if not row:
            return None
        return self._decrypt(row['encrypted_value'], row['salt'])

    async def list_history(self, identity_id: str) -> List[CredentialVersion]:
        async with self.pg_pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM credential_vault WHERE identity_id=$1 ORDER BY version DESC", identity_id)
        return [CredentialVersion(
            version=r['version'], identity_id=r['identity_id'], credential_id=r.get('credential_id'),
            encrypted_value='[REDACTED]', salt='[REDACTED]', hash_fingerprint=r['hash_fingerprint'],
            created_at=r['created_at'], created_by=r.get('created_by'),
            rotation_reason=r.get('rotation_reason'), is_active=r['is_active']) for r in rows]

    async def rollback(self, identity_id: str, to_version: int, rolled_back_by=None) -> CredentialVersion:
        old = await self.retrieve(identity_id, version=to_version)
        if old is None:
            raise ValueError(f"Version {to_version} not found")
        return await self.store(identity_id, old,
                                rotation_reason=f'Rollback to v{to_version}', created_by=rolled_back_by)

    async def rotate(self, identity_id: str, new_plaintext: str, created_by=None) -> CredentialVersion:
        return await self.store(identity_id, new_plaintext,
                                rotation_reason='Scheduled rotation', created_by=created_by)

    async def purge_old_versions(self, identity_id: str, keep: int = 10) -> int:
        async with self.pg_pool.acquire() as conn:
            result = await conn.execute("""
                DELETE FROM credential_vault WHERE identity_id=$1 AND is_active=false
                AND version NOT IN (SELECT version FROM credential_vault WHERE identity_id=$1 ORDER BY version DESC LIMIT $2)
            """, identity_id, keep)
        return int(result.split()[-1])

    async def verify_integrity(self, identity_id: str) -> bool:
        try:
            return await self.retrieve(identity_id) is not None
        except Exception:
            return False
