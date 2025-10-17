import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { HttpClient } from '@angular/common/http';

@Component({ selector: 'app-verify-email', template: '<p>{{msg}}</p>' })
export class VerifyEmailComponent implements OnInit {
  msg = 'Verifying...';
  api = (window as any).__env?.API_URL || 'http://localhost:4000/api';
  constructor(private route: ActivatedRoute, private http: HttpClient, private router: Router) {}
  ngOnInit() {
    const token = this.route.snapshot.queryParamMap.get('token');
    if (!token) { this.msg = 'Invalid token.'; return; }
    this.http.get(this.api + '/auth/verify-email?token=' + token).subscribe({
      next: () => { this.msg = 'Email verified. Redirecting to login...'; setTimeout(()=>this.router.navigate(['/login']),1500); },
      error: (e) => { this.msg = 'Verification failed: ' + (e.error?.error || e.message); }
    });
  }
}
