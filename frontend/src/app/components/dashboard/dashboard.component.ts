import { Component, OnInit } from '@angular/core';
import { AuthService } from '../services/auth.service';
import { SocketService } from '../services/socket.service';

@Component({ selector: 'app-dashboard', templateUrl: './dashboard.component.html' })
export class DashboardComponent implements OnInit {
  constructor(public auth: AuthService, private socket: SocketService) {}
  ngOnInit() { this.socket.connect(); this.socket.on('user-activity', (payload:any)=>console.log('activity',payload)); }
}
