import { Injectable } from '@angular/core';
import { io, Socket } from 'socket.io-client';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class SocketService {
  socket: Socket | null = null;
  constructor(private auth: AuthService) {}
  connect() {
    if (this.socket) return;
    this.socket = io((window as any).__env?.API_WS || 'http://localhost:4000', { withCredentials: true });
    this.socket.on('connect', () => {
      const token = this.auth.getToken();
      if (token) {
        try { const payload = JSON.parse(atob(token.split('.')[1])); this.socket!.emit('identify', { userId: payload.id }); } catch(e) {}
      }
    });
  }
  on(event: string, cb: (...args: any[]) => void) { this.connect(); this.socket!.on(event, cb); }
}
