#!/usr/bin/env python
#Unit2 User Signup project assignment

import webapp2
import re
import os
import jinja2


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)


class BaseHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class signup(BaseHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "Not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That is an invalid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords do not match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That is an invalid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.redirect("/welcome?username=" + str(username))


class welcome(BaseHandler):
    def get(self):
        username = self.request.get("username")
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('signup')


app = webapp2.WSGIApplication([('/', signup),
                               ('/welcome', welcome)], debug=True)
