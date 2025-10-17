import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpErrorResponse, HttpClient } from '@angular/common/http';
import { AuthService } from './auth.service';
import { Observable, throwError, from } from 'rxjs';
import { catchError, switchMap } from 'rxjs/operators';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private refreshing = false;
  constructor(private auth: AuthService, private http: HttpClient) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token = this.auth.getToken();
    let cloned = req;
    if (token) cloned = req.clone({ setHeaders: { Authorization: `Bearer ${token}` } });
    return next.handle(cloned).pipe(
      catchError((err: HttpErrorResponse) => {
        if (err.status === 401 && !req.headers.has('x-retried')) {
          // try refresh once
          if (this.refreshing) return throwError(() => err);
          this.refreshing = true;
          return this.http.post((this.auth.api) + '/auth/refresh-token', {}, { withCredentials: true }).pipe(
            switchMap((res: any) => {
              this.refreshing = false;
              if (res.token) this.auth.saveToken(res.token);
              const retry = req.clone({ setHeaders: { Authorization: `Bearer ${res.token}` , 'x-retried': '1' } });
              return next.handle(retry);
            }),
            catchError((e) => { this.refreshing = false; this.auth.logout(); return throwError(() => e); })
          );
        }
        return throwError(() => err);
      })
    );
  }
}
