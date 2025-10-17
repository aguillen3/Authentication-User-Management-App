import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
@Component({ selector: 'app-request-reset', template: `
  <h3>Request password reset</h3>
  <input [(ngModel)]="emailOrUsername" placeholder="email or username" />
  <button (click)="send()">Send</button>
  <p *ngIf="msg">{{msg}}</p>
` })
export class RequestResetComponent {
  emailOrUsername = '';
  msg = '';
  constructor(private auth: AuthService) {}
  send() {
    this.auth.requestPasswordReset(this.emailOrUsername).subscribe(()=>this.msg='If that account exists, an email was sent.');
  }
}
