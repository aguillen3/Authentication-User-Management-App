import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, interval } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable({ providedIn: 'root' })
export class AuthService {
  api = (window as any).__env?.API_URL || 'http://localhost:4000/api';
  tokenKey = 'auth_token';
  user$ = new BehaviorSubject<any>(null);

  private lastActivity = Date.now();
  private idleTimeout = 10 * 60 * 1000; // 10 minutes

  constructor(private http: HttpClient) {
    const token = localStorage.getItem(this.tokenKey);
    if (token) {
      this.saveToken(token);
      this.keepalive().subscribe({});
    }
    ['click', 'mousemove', 'keydown', 'touchstart'].forEach(evt =>
      window.addEventListener(evt, () => this.updateActivity())
    );
    interval(10000).subscribe(() => this.checkIdle());
  }

  private updateActivity() {
    this.lastActivity = Date.now();
    if (this.isLoggedIn()) { this.keepalive().subscribe({}); }
  }

  private checkIdle() {
    if (!this.isLoggedIn()) return;
    const now = Date.now();
    if (now - this.lastActivity > this.idleTimeout) {
      this.logout();
      alert('You have been logged out due to inactivity (10 minutes).');
    }
  }

  register(username: string, password: string, email?: string) {
    return this.http.post(this.api + '/auth/register', { username, password, email }).pipe(
      tap((res: any) => { if (res.token) this.saveToken(res.token); })
    );
  }

  login(username: string, password: string) {
    return this.http.post(this.api + '/auth/login', { username, password }).pipe(
      tap((res: any) => { if (res.token) this.saveToken(res.token); })
    );
  }

  saveToken(token: string) {
    localStorage.setItem(this.tokenKey, token);
    this.user$.next({}); // placeholder
    this.updateActivity();
  }

  getToken() { return localStorage.getItem(this.tokenKey); }
  isLoggedIn() { return !!this.getToken(); }
  logout() { localStorage.removeItem(this.tokenKey); this.http.post(this.api + '/auth/logout', {}).subscribe(()=>{}); this.user$.next(null); }
  deleteAccount() { return this.http.delete(this.api + '/auth/me'); }
  keepalive() { return this.http.post(this.api + '/auth/keepalive', {}); }
  requestPasswordReset(emailOrUsername: string) { return this.http.post(this.api + '/auth/request-password-reset', { emailOrUsername }); }
  resetPassword(token: string, password: string) { return this.http.post(this.api + '/auth/reset-password', { token, password }); }
}
