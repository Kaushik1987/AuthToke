import { Headers, Http, Response, Request } from '@angular/http';
import { Router } from '@angular/router';
import { Injectable, Inject } from '@angular/core';
import { Observable } from 'rxjs';

import { NotificationService } from './notification.service';
import { StateService } from './state.service';

/**
 * The auth service is used to communicate with the API in handling
 * all transactions related to authentication of users.
 */
@Injectable()
export class AuthService {
    constructor(
        @Inject('API_BASE') API_BASE: string,
        @Inject('API_VERSION') private API_VERSION: string,
        private http: Http,
        private notificationService: NotificationService,
        private router: Router,
        private stateService: StateService)
    {
        this.headers.append("content-type", "application/json");
        this.headers.append("api-version", API_VERSION);
        this.apiBase = API_BASE;
        this.apiAuthUrl = API_BASE + '/api/auth';
    }

    private apiBase: string;
    private apiAuthUrl: string;
    private headers: Headers = new Headers();

    /**
     * Calls the API to validate a users provided credentials
     * @param {string} username User provided username to use in authentication
     * @param {string} password User provided password to use in authentication
     */
    login(username: string, password: string): Observable<boolean> {
        let head: Headers = new Headers({
            'Content-Type': 'application/x-www-form-urlencoded',
            'api-version': this.API_VERSION
        });
        return this.http.post(
                            this.apiAuthUrl + '/token',
                                'username=' + username + '&password=' + password,
                                { headers: head })
            .flatMap((response) => {
                let token = response.json();
                if (token) {
                    return this.stateService.setToken(token);
                } else {
                    this.notificationService.notify('error', response.statusText);
                    return Observable.of(false);
                }
            });
    }

    /**
     * Removes any cookies and authorization for the currently logged in user
     */
    logout() {
        this.stateService.removeToken();
    }

    /**
     * Attempts to identify the user by the provided email address and emails them with a
     * URL to reset their password
     * @param {string} emailAddress User provided email address to find
     */
    forgot(emailAddress: string): Observable<Response> {
        let body = JSON.stringify({ emailAddress, domain: window.location.hostname});
        return this.http.post(this.apiAuthUrl + '/forgot', body, { headers: this.headers });
    }

    /**
     * Resets a users password if the provided hashCode is valid
     * @param {string} password New password to save to user account
     * @param {string} hashCode Hash that identifies a user
     */
    reset(password: string, hashCode: string): Observable<Response> {
        let body = JSON.stringify({ password, hashCode });
        return this.http.post(this.apiAuthUrl + '/reset', body, { headers: this.headers });
    }

    /**
     * Confirms that a provided reset hash is valid
     * @param {string} hashCode Hash that identifies a user
     */
    hashConfirm(hashCode: string): Observable<Response> {
        let body = JSON.stringify(hashCode);
        return this.http.post(this.apiAuthUrl + '/hash', body, { headers: this.headers });
    }

    /**
     * Confirms a user's email address is valid
     * @param {string} code System generated code that identifies a user
     */
    confirmEmail(code: string): Observable<Response> {
        let body = JSON.stringify(code);
        return this.http.post(this.apiAuthUrl + '/confirm', body, { headers: this.headers });
    }
}