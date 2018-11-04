import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';

import { AppComponent } from './app.component';
import { LoginComponent } from './components/login/login.component';
import { EncryptionComponent } from './components/encryption/encryption.component';
import { HashingComponent } from './components/hashing/hashing.component';
import { KeyGenerationComponent } from './components/key-generation/key-generation.component';
import { KeyStoreComponent } from './components/key-store/key-store.component';
import { SettingsComponent } from './components/settings/settings.component';
import { AuthenticationService } from './services/authentication.service';
import { AuthGuard } from './services/auth-guard.service';
import { KeyComponent } from './components/key-store/key.component';

const appRoutes : Routes = [
  { path: '', component: EncryptionComponent },
  { path: 'encryption', component: EncryptionComponent },
  { path: 'hashing', component: HashingComponent },
  { path: 'key-generation', component: KeyGenerationComponent },
  { path: 'key-store', canActivate: [AuthGuard], component: KeyStoreComponent },
  { path: 'login', component: LoginComponent },
  { path: 'settings', canActivate: [AuthGuard], component: SettingsComponent }
];

@NgModule({
  declarations: [
    AppComponent,
    EncryptionComponent,
    HashingComponent,
    KeyGenerationComponent,
    KeyStoreComponent,
    LoginComponent,
    SettingsComponent,
    KeyComponent
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
    RouterModule.forRoot(appRoutes),
    FormsModule
  ],
  providers: [AuthenticationService, AuthGuard],
  bootstrap: [AppComponent]
})
export class AppModule { }
