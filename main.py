import os

import re
from string import letters
import webapp2
import jinja2
import random
import hashlib
import hmac


from google.appengine.ext import ndb

from google.appengine.ext import db #all the above needed in support of program

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'im not telling'

def render_str(template, **params):  #unclear why this is here.  Not in video
    t = jinja_env.get_template(template) #but wont work without it.  
    return t.render(params)

def make_secure_val(val):  #returns secure val with hashed secret
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):   #validates secure value with secret
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler): #3 things which are copied
    def write(self, *a, **kw): #writes to client browser
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params): #this makes it easier for instructor
        params['user'] = self.user  #renders html.  Still trying to understand
        return render_str(template, **params)

    def render(self, template, **kw):
	    self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name): #rerturns cookie value
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):  #validates user
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):     #clears login info
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

'''def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')# this is to allow for line breaks
    response.out.write(post.content)'''

class MainPage(BlogHandler): #this is main page of url
    def get(self):  # not needed for blog
      self.write('Hello, Udacity!!!')

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):  #this is not needed but provides for a parent relationship
	return db.Key.from_path('blogs', name)#sets stage for multiple blogs

class Post(db.Model):
    subject=db.StringProperty(required=True) #look up StringProperty, TextProperty, etc
    content=db.TextProperty(required=True) #text property can be greater than 500 characters
    #string property can be indexed but text property cannot
    created=db.DateTimeProperty(auto_now_add=True)#auto_now_add is a time stamp
    last_modified=db.DateTimeProperty(auto_now=True)#lists time last updated

    def render(self):  #renders blog entry
        self._render_text=self.content.replace('\n', '<br>')#inputs new lines for html line breaks
        return render_str("post.html", p=self)

class BlogFront(BlogHandler):
    def get(self):
        deleted_post_id = self.request.get('deleted_post_id')
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts, deleted_post_id=deleted_post_id) 
		#renders result of above query in front.html stored in variable 'posts'

class PostPage(BlogHandler):
    def get(self, post_id): #gets passed in from below but numbers now assigned randomly
        key=db.Key.from_path('Post', int(post_id), parent=blog_key())
	    #parent only needed because parent was created.  this section is not fully understood
        post=db.get(key)

        comments=db.GqlQuery("select * from Comment where post_id = " +post_id+" order by created desc")

        likes=db.GqlQuery("select * from Like where post_id="+post_id)

        if not post:
            self.error(404)
            return

        error=self.request.get('error')

        self.render("permalink.html", post=post, noOfLikes=likes.count(),
                    comments=comments, error=error)
        
    def post(self, post_id):
        key=db.Key.from_path('Post', int(post_id), parent=blog_key())
        post=db.get(key)

        if not post:
            self.error(404)
            return #when posting comment, new comment is created&stored

        c = ""
        if(self.user):
            if(self.request.get('like') and self.request.get('like')=="update"):
                likes=db.GqlQuery("select * from Like where post_id = " +
                                    post_id +" and user_id = "+str(self.user.key().id()))

                if self.user.key().id()==post.user_id:
                    self.redirect("/blog/"+post_id +"error=immodest to like your own post!!")
                    return

                elif likes.count()==0:
                    l =Like(parent=blog_key(), user_id=self.user.key().id(), post_id=int(post_id))
                    l.put()

            if(self.request.get('comment')):
                c=Comment(parent=blog_key(), user_id=self.user.key().id(), post_id=int(post_id),
                            comment=self.request.get('comment'))
                c.put()
        else:
            self.redirect("login error=You need to login before 'editing' 'liking' or 'commenting'")
            return

        comments=db.GqlQuery("select * from Comment where post_id = post_id order by created desc")

        likes=db.GqlQuery("select * from Like where post_id="+post_id)

        self.render("permalink.html", post=post, comments=comments, noOfLikes=likes.count(), new=c)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content: #if subject and content there
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()#stores element in database
            self.redirect('/blog/%s' % str(p.key().id()))
            #redirects user to above to get id in datastore
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

'''class DeletePost(BlogHandler):
    def get(self):
        if self.user:
            post_id = self.request.get("post")
            key = ndb.Key('BlogPost', int(post_id) parent=blog_key())
            post = key.get()
            if not post:
                self.error(404)
                return
            self.render("deletepost.html", post=post)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect("/login")
        post_id = self.request.get("post")
        key = ndb.Key('BlogPost', int(post_id) parent=blog_key())
        post = key.get()
        if post and post.author.username == self.user.username:
            key.delete()
        self.redirect("/blog")'''

class DeletePost(BlogHandler):
    def get(self):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/?deleted_post_id="+post_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this record.")
        else:
            self.redirect("/login?error=You need to be logged, in order" +
                          " to delete your post!!")


class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to edit this record.")
        else:
            self.redirect("/login?error=You need to be logged, " +
                          "in order to edit your post!!")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                c.delete()
                self.redirect("/blog/"+post_id+"?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to " +
                          "delete your comment!!")


class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                self.render("editcomment.html", comment=c.comment)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=You don't have access to edit this " +
                              "comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to" +
                          " edit your post!!")

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            c = db.get(key)
            c.comment = comment
            c.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$") #validates username
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")   #validates PW
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')  #validates email
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "Invalid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Invalid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Password mismatch."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Invalid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

#class Unit2Signup(Signup):
#    def done(self):
#        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'Duplicate user exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit3/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                              # ('/unit2/signup', Unit2Signup),
                              # ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/deletepost/?', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)', EditComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/?', BlogFront)
                               ],
							debug=True)
