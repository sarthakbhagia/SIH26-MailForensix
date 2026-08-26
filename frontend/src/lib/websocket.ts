import { Alert } from '../types/alert';

export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'reconnecting' | 'error';
export type AlertHandler = (alert: Alert) => void;
export type StatusHandler = (status: ConnectionStatus) => void;

export class WebSocketManager {
  private ws: WebSocket | null = null;
  private reconnectTimeoutId: any = null;
  private heartbeatIntervalId: any = null;
  private baseReconnectDelay: number = 1000;
  private maxReconnectDelay: number = 30000;
  private currentReconnectDelay: number = 1000;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 10;
  private isIntentionalDisconnect: boolean = false;
  private listeners: Set<AlertHandler> = new Set();
  private statusListeners: Set<StatusHandler> = new Set();
  public onAlert: AlertHandler | null = null;
  public status: ConnectionStatus = 'disconnected';

  private getUrl(): string {
    if (typeof window === 'undefined') {
      return 'ws://localhost:8000/api/alerts/ws';
    }
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${protocol}//${host}/api/alerts/ws`;
  }

  private setStatus(newStatus: ConnectionStatus) {
    this.status = newStatus;
    this.statusListeners.forEach((listener) => {
      try {
        listener(newStatus);
      } catch (err) {
        console.error('Error in status listener:', err);
      }
    });
  }

  public onStatusChange(handler: StatusHandler): () => void {
    this.statusListeners.add(handler);
    handler(this.status);
    return () => {
      this.statusListeners.delete(handler);
    };
  }

  public subscribe(handler: AlertHandler): () => void {
    this.listeners.add(handler);
    if (this.status === 'disconnected') {
      this.connect();
    }
    return () => {
      this.listeners.delete(handler);
    };
  }

  public connect(url?: string): void {
    if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) {
      return;
    }

    this.isIntentionalDisconnect = false;
    this.clearTimers();
    this.setStatus(this.reconnectAttempts > 0 ? 'reconnecting' : 'connecting');

    const targetUrl = url || this.getUrl();

    try {
      this.ws = new WebSocket(targetUrl);

      this.ws.onopen = () => {
        this.setStatus('connected');
        this.reconnectAttempts = 0;
        this.currentReconnectDelay = this.baseReconnectDelay;
        this.startHeartbeat();
      };

      this.ws.onmessage = (event: MessageEvent) => {
        try {
          const raw = event.data;
          if (raw === 'pong' || raw === '{"type":"pong"}' || raw === '{"type": "pong"}') {
            return;
          }
          const parsed = JSON.parse(raw);
          if (parsed && parsed.type === 'pong') {
            return;
          }
          const alert: Alert = parsed;
          if (this.onAlert) {
            this.onAlert(alert);
          }
          this.listeners.forEach((listener) => {
            try {
              listener(alert);
            } catch (err) {
              console.error('Error in alert listener:', err);
            }
          });
        } catch (error) {
          console.error('WebSocket alert message parsing error:', error);
        }
      };

      this.ws.onerror = (error) => {
        console.warn('WebSocket error observed:', error);
        this.setStatus('error');
      };

      this.ws.onclose = () => {
        this.stopHeartbeat();
        this.ws = null;
        if (!this.isIntentionalDisconnect) {
          this.setStatus('disconnected');
          this.scheduleReconnect(targetUrl);
        } else {
          this.setStatus('disconnected');
        }
      };
    } catch (error) {
      console.warn('Failed to initiate WebSocket connection:', error);
      this.setStatus('error');
      if (!this.isIntentionalDisconnect) {
        this.scheduleReconnect(targetUrl);
      }
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatIntervalId = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        try {
          this.ws.send(JSON.stringify({ type: 'ping' }));
        } catch (e) {
          console.warn('Failed to send heartbeat ping:', e);
        }
      }
    }, 30000);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatIntervalId) {
      clearInterval(this.heartbeatIntervalId);
      this.heartbeatIntervalId = null;
    }
  }

  private scheduleReconnect(url: string): void {
    if (this.isIntentionalDisconnect) {
      return;
    }

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.warn(`WebSocket reached max reconnect attempts (${this.maxReconnectAttempts}). Stopping auto-reconnect.`);
      this.setStatus('disconnected');
      return;
    }

    this.reconnectAttempts += 1;
    this.setStatus('reconnecting');

    this.reconnectTimeoutId = setTimeout(() => {
      this.currentReconnectDelay = Math.min(this.currentReconnectDelay * 2, this.maxReconnectDelay);
      this.connect(url);
    }, this.currentReconnectDelay);
  }

  private clearTimers(): void {
    if (this.reconnectTimeoutId) {
      clearTimeout(this.reconnectTimeoutId);
      this.reconnectTimeoutId = null;
    }
    this.stopHeartbeat();
  }

  public disconnect(): void {
    this.isIntentionalDisconnect = true;
    this.clearTimers();
    this.reconnectAttempts = 0;
    this.currentReconnectDelay = this.baseReconnectDelay;

    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.setStatus('disconnected');
  }
}

export const wsManager = new WebSocketManager();

