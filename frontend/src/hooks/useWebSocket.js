/**
 * NHI Shield - Real-time WebSocket Hook
 * Connects to Socket.IO server for live dashboard updates
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { io } from 'socket.io-client';

const SOCKET_URL = process.env.REACT_APP_API_URL?.replace('/api', '') || 'http://localhost:3000';

/**
 * @param {string[]} events - List of event names to listen to
 * @returns {{ connected, lastEvent, on, emit, reconnect }}
 */
const useWebSocket = (events = []) => {
  const socketRef = useRef(null);
  const [connected, setConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState(null);
  const handlersRef = useRef({});

  const connect = useCallback(() => {
    const token = localStorage.getItem('token');
    if (!token) return;

    // Disconnect existing socket if any
    if (socketRef.current) {
      socketRef.current.disconnect();
    }

    const socket = io(SOCKET_URL, {
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      timeout: 10000,
    });

    socket.on('connect', () => {
      console.log('🔌 NHI Shield WebSocket connected');
      setConnected(true);
    });

    socket.on('disconnect', (reason) => {
      console.log('🔌 WebSocket disconnected:', reason);
      setConnected(false);
    });

    socket.on('connect_error', (err) => {
      console.warn('WebSocket connection error:', err.message);
      setConnected(false);
    });

    // Register all requested event listeners
    events.forEach(eventName => {
      socket.on(eventName, (data) => {
        const event = { type: eventName, data, timestamp: new Date().toISOString() };
        setLastEvent(event);
        // Call any registered handlers for this event
        if (handlersRef.current[eventName]) {
          handlersRef.current[eventName].forEach(handler => handler(data));
        }
      });
    });

    socketRef.current = socket;
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    connect();
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
    };
  }, [connect]);

  /**
   * Register a handler for a specific event
   */
  const on = useCallback((eventName, handler) => {
    if (!handlersRef.current[eventName]) {
      handlersRef.current[eventName] = [];
    }
    handlersRef.current[eventName].push(handler);

    // Also register on socket if already connected
    if (socketRef.current) {
      socketRef.current.on(eventName, handler);
    }

    // Return cleanup function
    return () => {
      handlersRef.current[eventName] = (handlersRef.current[eventName] || []).filter(h => h !== handler);
      if (socketRef.current) {
        socketRef.current.off(eventName, handler);
      }
    };
  }, []);

  /**
   * Emit an event to the server
   */
  const emit = useCallback((eventName, data) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit(eventName, data);
    }
  }, []);

  return { connected, lastEvent, on, emit, reconnect: connect };
};

export default useWebSocket;
