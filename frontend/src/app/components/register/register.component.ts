import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({ selector: 'app-register', templateUrl: './register.component.html' })
export class RegisterComponent {
  username = ''; password = ''; email='';
  constructor(private auth: AuthService, private router: Router) {}
  register() {
    this.auth.register(this.username, this.password, this.email).subscribe({ next: () => this.router.navigate(['/']), error: (err) => alert(err.error?.error || 'Registration failed') });
  }
}
