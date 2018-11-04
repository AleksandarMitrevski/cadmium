import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticationService } from './services/authentication.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  constructor (private router: Router, public auth: AuthenticationService) { }

  onLogout() {
    this.auth.logout();
    if(this.router.url === '/key-store' || this.router.url === '/settings') {
      this.router.navigate(["/encryption"]);
    }
    return false;
  }
}
