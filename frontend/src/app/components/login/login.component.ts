import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({ selector: 'app-login', templateUrl: './login.component.html' })
export class LoginComponent {
  username = ''; password = '';
  constructor(private auth: AuthService, private router: Router) {}
  login() {
    this.auth.login(this.username, this.password).subscribe({
      next: () => this.router.navigate(['/']),
      error: (err) => alert(err.error?.error || 'Login failed')
    });
  }
}
