import { Component, OnInit } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { SocketService } from '../../services/socket.service';
import { AuthService } from '../../services/auth.service';

@Component({ selector: 'app-admin', templateUrl: './admin.component.html' })
export class AdminComponent implements OnInit {
  api = (window as any).__env?.API_URL || 'http://localhost:4000/api';
  users: any[] = [];
  tokens: any[] = [];
  search = ''; from=''; to=''; active='';
  stats: any = null;
  connectedUsers: any[] = [];
  selectedUserId: number | null = null;
  constructor(private http: HttpClient, private socket: SocketService, public auth: AuthService) {}
  ngOnInit() { this.load(); this.loadStats(); this.socket.on('user-registered', ()=>this.load()); this.socket.on('user-deleted', ()=>this.load()); this.socket.on('connected-users', (list)=>this.connectedUsers = list); }
  load() {
    let params = new HttpParams();
    if (this.search) params = params.set('q', this.search);
    if (this.from) params = params.set('from', this.from);
    if (this.to) params = params.set('to', this.to);
    if (this.active) params = params.set('active', this.active);
    this.http.get(this.api + '/admin/users', { params }).subscribe((res: any) => this.users = res.users);
  }
  loadStats() { this.http.get(this.api + '/admin/stats').subscribe((res:any)=>this.stats=res); }
  deactivate(id:number){ this.http.post(this.api+`/admin/users/${id}/deactivate`,{}).subscribe(()=>this.load()); }
  deleteUser(id:number){ this.http.delete(this.api+`/admin/users/${id}`).subscribe(()=>this.load()); }
  viewTokens(userId:number){ this.selectedUserId=userId; this.http.get(this.api+`/admin/users/${userId}/refresh-tokens`).subscribe((res:any)=> this.tokens=res.tokens); }
  revokeToken(id:number){ this.http.post(this.api+`/admin/refresh-tokens/${id}/revoke`,{}).subscribe(()=> this.viewTokens(this.selectedUserId!)); }
}
