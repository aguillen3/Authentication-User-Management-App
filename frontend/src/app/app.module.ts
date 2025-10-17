import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { AppComponent } from './app.component';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { AdminComponent } from './components/admin/admin.component';
import { VerifyEmailComponent } from './components/verify-email/verify-email.component';
import { RequestResetComponent } from './components/request-reset/request-reset.component';
import { ResetPasswordComponent } from './components/reset-password/reset-password.component';
import { AuthInterceptor } from './services/auth.interceptor';

@NgModule({
  declarations: [AppComponent, LoginComponent, RegisterComponent, DashboardComponent, AdminComponent, VerifyEmailComponent, RequestResetComponent, ResetPasswordComponent],
  imports: [BrowserModule, HttpClientModule, FormsModule, RouterModule.forRoot([
    { path: '', component: DashboardComponent },
    { path: 'login', component: LoginComponent },
    { path: 'register', component: RegisterComponent },
    { path: 'admin', component: AdminComponent },
    { path: 'verify-email', component: VerifyEmailComponent },
    { path: 'request-reset', component: RequestResetComponent },
    { path: 'reset-password', component: ResetPasswordComponent }
  ])],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true }
  ],
  bootstrap: [AppComponent]
})
export class AppModule {}
