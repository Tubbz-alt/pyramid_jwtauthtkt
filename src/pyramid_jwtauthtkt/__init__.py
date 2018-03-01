#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pyramid.security import remember
from .policy import JWTAuthTktAuthenticationPolicy

def includeme(config):
    config.add_directive('set_jwtauthtkt_authentication_policy',
                         _set_authentication_policy,
                         action_wrap=True)

def _set_authentication_policy(config,
    # pyramid.authentication.CallbackAuthenticationPolicy
    callback=None, debug=False,
    # pyramid.authentication.AuthTktAuthenticationPolicy
    secret=None, cookie_name='auth_tkt', secure=False, include_ip=False,
    timeout=None, reissue_time=None, max_age=None, path='/', http_only=False,
    wild_domain=True, hashalg='sha512', parent_domain=False, domain=None,
    # based on JWTAuthenticationPolicy
    private_key=None, public_key=None, algorithm='HS512',
    expiration=None, leeway=0):

    settings = config.get_settings()
    # Callback options
    debug       = settings.get('auth.debug')           or debug
    # AuthTkt options
    secret      = settings.get('auth.tkt.secret')      or secret
    cookie_name = settings.get('auth.tkt.cookie_name') or cookie_name
    secure      = settings.get('auth.tkt.secure')      or secure
    http_only   = settings.get('auth.tkt.http_only')   or http_only
    domain      = settings.get('auth.tkt.domain')      or domain
    # JWT options
    private_key = settings.get('auth.jwt.private_key') or private_key
    public_key  = settings.get('auth.jwt.public_key')  or public_key or private_key
    algorithm   = settings.get('auth.jwt.algorithm')   or algorithm
    if expiration is None and 'auth.jwt.expiration' in settings:
        expiration = int(settings.get('auth.jwt.expiration'))
    leeway = int(settings.get('auth.jwt.leeway', 0)) if leeway is None else leeway

    policy = JWTAuthTktAuthenticationPolicy(callback, debug,
        secret, cookie_name, secure, include_ip, timeout, reissue_time, max_age,
        path, http_only, wild_domain, hashalg, parent_domain, domain,
        private_key, public_key, algorithm, expiration, leeway)

    def _new_tokens(request, principal, expiration=None, **claims):
        csrf_token = policy.new_csrf_token(request)
        jwt_token  = policy.new_jwt_token(principal, csrf_token, expiration, **claims)
        # update Request.response headers
        if 'Set-Cookie' in request.response.headers:
            del request.response.headers['Set-Cookie']
        request.response.headerlist.extend(remember(request, jwt_token))
        request.response.headers['X-CSRF-Token'] = csrf_token
        return True

    def _get_claims(request):
        return policy.get_jwt_claims(request)

    config.set_default_csrf_options(token=None)
    config.set_csrf_storage_policy(policy)
    config.set_authentication_policy(policy)
    config.add_request_method(_new_tokens, 'new_tokens')
    config.add_request_method(_get_claims, 'get_claims', reify=True)
