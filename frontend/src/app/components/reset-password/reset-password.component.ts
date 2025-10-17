import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({ selector: 'app-reset-password', template: `
  <h3>Reset password</h3>
  <p *ngIf="msg">{{msg}}</p>
  <div *ngIf="!done">
    <input [(ngModel)]="password" placeholder="new password" type="password" />
    <button (click)="reset()">Reset</button>
  </div>
` })
export class ResetPasswordComponent implements OnInit {
  token = '';
  password = '';
  msg = '';
  done = false;
  constructor(private route: ActivatedRoute, private auth: AuthService, private router: Router) {}
  ngOnInit() { this.token = this.route.snapshot.queryParamMap.get('token') || ''; if(!this.token) this.msg='Invalid token'; }
  reset() {
    this.auth.resetPassword(this.token, this.password).subscribe(() => { this.msg='Password reset. Redirecting to login...'; this.done=true; setTimeout(()=>this.router.navigate(['/login']),1500); }, err => this.msg='Failed: '+(err.error?.error||err.message));
  }
}
