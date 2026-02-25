// ============================================================
// NHI SHIELD — Logger Service
// Uses Winston with structured JSON logging
// ============================================================
const winston = require('winston');
const path = require('path');

const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const LOG_DIR = path.join(__dirname, '../../../../logs');

// Custom format: timestamp + level + message + metadata
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
);

// Pretty format for development console
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
        return `${timestamp} [${level}] ${message}${metaStr}`;
    })
);

const transports = [
    // Always write to console
    new winston.transports.Console({
        format: process.env.NODE_ENV === 'production' ? logFormat : consoleFormat,
    }),
];

// In production, also write to rotating log files
if (process.env.NODE_ENV === 'production') {
    const DailyRotateFile = require('winston-daily-rotate-file');

    transports.push(
        new DailyRotateFile({
            dirname: LOG_DIR,
            filename: 'nhi-shield-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxFiles: '30d',      // Keep 30 days of logs
            maxSize: '100m',
            zippedArchive: true,
            format: logFormat,
        })
    );

    // Separate file for errors only
    transports.push(
        new DailyRotateFile({
            dirname: LOG_DIR,
            filename: 'nhi-shield-error-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            level: 'error',
            maxFiles: '90d',
            zippedArchive: true,
            format: logFormat,
        })
    );
}

const logger = winston.createLogger({
    level: LOG_LEVEL,
    levels: {
        ...winston.config.npm.levels,
        http: 5,  // Custom level for HTTP request logging
    },
    transports,
    // Never crash the process on logger errors
    exitOnError: false,
});

// Add http level color
winston.addColors({ http: 'cyan' });

module.exports = logger;
