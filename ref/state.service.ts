import { Inject, Injectable } from '@angular/core';
import { Headers, Http, Response } from '@angular/http';
import { Title } from '@angular/platform-browser';
import { ActivatedRouteSnapshot, Router } from '@angular/router';
import { Observable } from 'rxjs';
import { CookieService } from 'angular2-cookie/services/cookies.service';

import { MenuItem } from '../../shared/models/menu-item.model';
import { User } from "../../shared/models/user.model";

/**
 * The state service manages all authentication/authorization capabilities
 */
@Injectable()
export class StateService {
    constructor(
        @Inject('API_BASE') private API_BASE: string,
        @Inject('API_VERSION') private API_VERSION: string,
        private _cookieService: CookieService,
        private _http: Http,
        private _title: Title,
        private _router: Router) {

        this.apiUrl = API_BASE + '/api';
        let userToken: string = this._cookieService.get('user_token');

        if (userToken) {
            let parsedToken: any = this.parseToken(userToken); 
            this.currentUser = parsedToken;

            let userPermissions: any = this._cookieService.get("user_permissions");
            if (userPermissions == null) {
                this.loadPermissions().subscribe(s => {});
            }
            else {
                this.permissions = userPermissions;
            }
        }
    }
    
    private apiUrl: string;

    /**
     * If authenticated, the current user object
     */
    public currentUser: any;

    private permissions: string[]; 

    private parseToken(jwt: any) {
        let base64Url = jwt.split('.')[1];
        if (base64Url != null) {
            let base64 = base64Url.replace('-', '+').replace('_', '/');
            return JSON.parse(window.atob(base64));
        }
        return null;
    }

    /**
     * Attempts to refresh the JWT auth token with the refresh token
     */
    public refreshToken(): Observable<Headers> {
        let refreshToken = this._cookieService.get('refresh_token');
        if (refreshToken) {
            let refreshHeader = new Headers();
            refreshHeader.append('Authorization', 'Bearer ' + refreshToken);
            refreshHeader.append("api-version", this.API_VERSION);

            return this._http.post(this.apiUrl + '/auth/refresh/' + refreshToken, null, { headers: refreshHeader })
                .map(res => {
                    let jwt = res.json();
                    this.setToken(jwt).subscribe(
                        s => {
                            let headers = new Headers();
                            headers.append("content-type", "application/json");
                            headers.append("api-version", this.API_VERSION);
                            headers.append('Authorization', 'Bearer ' + jwt.access_token);
                            return headers;
                        });
                }).catch(err => {
                    this.removeToken();
                    return Observable.throw(err);
                });
        }
        else {
            return new Observable<Headers>((obs: any) => {
                this.removeToken();
                obs.error(new Error('No refresh token available.'));
            });
        }
    }

    /**
     * Gets a Header object with the Authorization: Bearer {token}
     */
    public getAuthHeader(): Observable<any>  {
        let token: string = this._cookieService.get('user_token');
        
        if (token) {
            let params = this.parseToken(token);
            if (params && Math.round(new Date().getTime() / 1000) <= params.exp) {
                let headers = new Headers();
                headers.append("content-type", "application/json");
                headers.append("api-version", this.API_VERSION);
                headers.append('Authorization', 'Bearer ' + token);
                return Observable.of(headers);
            }
        }
        
        return this.refreshToken();
    }

    /**
     * Saves JWT authentication/authorization token to cookies and sets
     * current user object.
     * @param jwt
     */
    public setToken(jwt: any): Observable<any>  {
        let oneYearFromNow = new Date();
        oneYearFromNow.setFullYear(oneYearFromNow.getFullYear() + 1);

        this.currentUser = this.parseToken(jwt.access_token);

        this._cookieService.put('user_token', jwt.access_token, { expires: oneYearFromNow });

        if (jwt.refresh_token) {
            this._cookieService.put('refresh_token', jwt.refresh_token, { expires: oneYearFromNow });
        }

        return this.loadPermissions();
    }

    /**
     * Removes the current token to de-authenticate the current user
     */
    public removeToken() {
        this.currentUser = null;
        this.permissions = null;
        this._cookieService.removeAll();
        this._router.navigate(['/auth']);
    }

    /**
     * Validates whether the current user has access to the route for the menu item
     * @param {MenuItem} menuItem The menu item to validate relative to the users privileges
     */
    public canTraverseRoute(menuItem: MenuItem): boolean {
        if (this.currentUser == null) {
            return false;
        }

        // user is authenticated and the route requires no special privilege
        if (menuItem.requiredPrivileges == null || menuItem.requiredPrivileges.length == 0) {
            return true;
        }
        else {
            let privileges = menuItem.requiredPrivileges;
            let permissions = this.permissions;
            if (permissions) {
                return privileges.some(function (v) {
                    return permissions.indexOf(v) >= 0;
                });
            }
        }

        return false;
    }

    /**
     * Validates whether the current user has the requested privilege
     * @param {string} privilege The privilege required of the current user
     */
    public hasPrivilege(privilege: string): boolean {
        if (this.currentUser == null) {
            return false;
        }

        let permissions = this.permissions;
        if (permissions) {
            return permissions.indexOf(privilege) >= 0;
        }

        return false;
    }

    private loadPermissions(): Observable<any> {
        let headers = new Headers();
        return this.getAuthHeader()
            .flatMap(authHeaders => {
                headers.forEach((val, name) => authHeaders.append(name, val[0]));
                let requestUrl: string = this.apiUrl + '/common/access';
                return this._http.get(requestUrl, { headers: authHeaders })
                    .flatMap(s => {
                        let perms = s.json();
                        this.permissions = perms;

                        let oneYearFromNow = new Date();
                        oneYearFromNow.setFullYear(oneYearFromNow.getFullYear() + 1);
                        this._cookieService.put('user_permissions', perms, { expires: oneYearFromNow });

                        return Observable.of(true);
                    });
            });
    }
}