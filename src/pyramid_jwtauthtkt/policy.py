#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import logging
import jwt
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.compat import bytes_, text_
from pyramid.interfaces import IAuthenticationPolicy, ICSRFStoragePolicy
from pyramid.util import strings_differ
from uuid import uuid4
from zope.interface import implementer

log = logging.getLogger('pyramid_jwtauthtkt')

@implementer(IAuthenticationPolicy)
@implementer(ICSRFStoragePolicy)
class JWTAuthTktAuthenticationPolicy(AuthTktAuthenticationPolicy):

    def __init__(self,
        # pyramid.authentication.CallbackAuthenticationPolicy
        callback=None, debug=False,
        # pyramid.authentication.AuthTktAuthenticationPolicy
        secret=None, cookie_name='auth_tkt', secure=False, include_ip=False,
        timeout=None, reissue_time=None, max_age=None, path='/', http_only=False,
        wild_domain=True, hashalg='sha512', parent_domain=False, domain=None,
        # based on JWTAuthenticationPolicy
        private_key=None, public_key=None, algorithm='HS512',
        expiration=None, leeway=0):

        # AuthTktAuthenticationPolicy.__init__
        super().__init__(secret,
            callback=callback,
            cookie_name=cookie_name, secure=secure, include_ip=include_ip,
            timeout=timeout, reissue_time=reissue_time, max_age=max_age,
            path=path, http_only=http_only, wild_domain=wild_domain,
            debug=debug, hashalg=hashalg, parent_domain=parent_domain, domain=domain)

        # JWT
        self.private_key    = private_key
        self.public_key     = public_key if public_key is not None else private_key
        self.algorithm      = algorithm
        if expiration:
            if not isinstance(expiration, datetime.timedelta):
                expiration = datetime.timedelta(seconds=expiration)
            self.expiration = expiration
        else:
            self.expiration = None
        self.leeway         = leeway

    def new_jwt_token(self, principal, csrf_token, expiration=None, **claims):
        payload = claims.copy()
        payload['sub'] = principal
        payload['iat'] = iat = datetime.datetime.utcnow()
        # CSRF uses 'jti' https://tools.ietf.org/html/rfc7519#section-4.1.7
        payload['jti'] = csrf_token
        expiration = expiration or self.expiration
        if expiration:
            if not isinstance(expiration, datetime.timedelta):
                expiration = datetime.timedelta(seconds=expiration)
            payload['exp'] = iat + expiration
        token = jwt.encode(payload, self.private_key, algorithm=self.algorithm)
        if not isinstance(token, str):
            token = token.decode('ascii')
        return token

    def get_jwt_claims(self, request):
        """ JWT claims:
            stored in cookie using AuthTktCookieHelper
        """
        identity = self.cookie.identify(request)
        if not identity: # no cookie == no claims
            return {}
        # FAQ: AuthTktCookieHelper uses 'userid', thus JWT token stored there
        token = identity.get('userid', None)
        if not token: # no JWT in cookie == no claims
            return {}
        try:
            claims = jwt.decode(token, self.public_key,
                                algorithms=[self.algorithm], leeway=self.leeway)
        except jwt.InvalidTokenError as e:
            log.warning('INVALID JWT TOKEN [REMOTE_ADDR: %s] %s',
                        request.remote_addr, e)
            return {}
        return claims

    # IAuthenticationPolicy
    def unauthenticated_userid(self, request):
        return request.get_claims.get('sub')

    def remember(self, request, userid, **kw):
        return self.cookie.remember(request, userid, **kw)

    def forget(self, request):
        return self.cookie.forget(request)

    # ICSRFStoragePolicy
    def new_csrf_token(self, request):
        return text_(uuid4().hex)

    def get_csrf_token(self, request):
        """ Returns currently active CSRF token by checking cookie,
        generating a new one if needed."""
        csrf_token = request.get_claims.get('jti', None)
        if not csrf_token:
            return self.new_csrf_token(request)
        return csrf_token

    def check_csrf_token(self, request, supplied_token):
        """ Returns ``True`` if the ``supplied_token`` is valid."""
        expected_token = self.get_csrf_token(request)
        return not strings_differ(
            bytes_(expected_token), bytes_(supplied_token))
