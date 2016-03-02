import cgi
import urllib
import urllib2
import json
import hashlib
import hmac
import base64

from google.appengine.ext import ndb

import webapp2

#let's define constants
OUI = '<html><head><link rel="stylesheet" href="//d2uaiq63sgqwfs.cloudfront.net/8.0.0/oui.css"><link rel="stylesheet" href="//d2uaiq63sgqwfs.cloudfront.net/8.0.0/oui-extras.css"></head><body style="padding-left:50px;padding-top:30px">'
client_secret = ###YOUR SECRET HERE###

#let's define HTML templates for pages
MAIN_PAGE_TEMPLATE = OUI + """\
    <div><h1>Welcome to MUV Limiter!</h1></div>
    <hr>
    %s
    <hr>
    <div><h2>Set limits for a test</h2></div>
    <form action="/confirmation" method="post">
      Test ID:<br>
      <input type="text" name="test_id">
      <br>
      MUV Limit:<br>
      <input type="text" name="muv_limit">
      <div><input type="submit" value="Submit"></div>
    </form>
    <hr>
    <div><h2>See status for all previously registered tests</h2></div>
    <a href="/lookup">Lookup status now!</a><br>
    <a href="/cron">Run Cron now!</a>
  </body>
</html>
"""

CONFIRMATION_PAGE_TEMPLATE = OUI + """\
    <div><h1>Ok, we made a new entry</h1></div>
    <div>Account ID: %s</div>
    <div>Test ID: %s</div>
    <div>MUV Limit: %s</div>
    <div>Current Usage: %s</div>
    <div>Status: %s</div>
    <hr>
    <a href="/">Go back</a>
  </body>
</html>
"""

LOOKUP_PAGE_TEMPLATE = OUI + """\
    <div><h1>Here are all running registered tests:</h1></div>
    <div>%s</div>
    <a href="/">Go back</a>
  </body>
</html>
"""

CRON_PAGE_TEMPLATE = """\
<html>
    <body>
    <div>%s</div>
    </body>
</html>
"""

#define method for verifying context payload
def verify_context(query_string):
    signed_request = urllib.unquote(query_string.split("signed_request=")[1]).decode('utf8').split('.')
    hashed_base64_context = signed_request[0]
    unhashed_base64_context = signed_request[1]
    HMAC_hash = hmac.new(client_secret, unhashed_base64_context, digestmod=hashlib.sha256).hexdigest().lower()
    b64encoded_hash = base64.b64encode(HMAC_hash)
    if b64encoded_hash == hashed_base64_context:
        return json.loads(base64.b64decode(unhashed_base64_context))
    else:
        return False

#let's define our API methods
def rest_api_get(test_info, endpoint):
    if endpoint:
        url = "https://www.optimizelyapis.com/experiment/v1/experiments/%s/%s" % (test_info.test_id, endpoint)
    else:
        url = "https://www.optimizelyapis.com/experiment/v1/experiments/%s" % (test_info.test_id)
    api_request = urllib2.Request(url)

    #get parent account_info
    account_info = ndb.Key(Account_info, test_info.account_id).get()

    api_request.add_header("Authorization", "Bearer " + account_info.session_token)
    api_response = json.loads(urllib2.urlopen(api_request, None, 60).read())
    return api_response

def rest_api_put(test_info, endpoint, data):
    if endpoint:
        url = "https://www.optimizelyapis.com/experiment/v1/experiments/%s/%s" % (test_info.test_id, endpoint)
    else:
        url = "https://www.optimizelyapis.com/experiment/v1/experiments/%s" % (test_info.test_id)

    #get parent account_info
    account_info = ndb.Key(Account_info, test_info.account_id).get()

    headers = {'Authorization': "Bearer " + account_info.session_token, 'Content-type': 'application/json'}
    opener = urllib2.build_opener(urllib2.HTTPHandler)
    request = urllib2.Request(url, data=json.dumps(data), headers=headers)
    request.get_method = lambda: 'PUT'
    return opener.open(request)

def set_current_muvs(test_info):
    api_response = rest_api_get(test_info, "stats")
    seen_vars = []
    current_muvs = 0
    for entry in api_response:
        if entry["variation_id"] not in seen_vars:
            seen_vars.append(entry["variation_id"])
            current_muvs += entry["visitors"]
    test_info.current_muvs = current_muvs


#let's define our database entities
class Account_info(ndb.Model):
    session_token = ndb.StringProperty(indexed=False)
    account_id = ndb.IntegerProperty(indexed=True)


class Test_info(ndb.Model):
    account_id = ndb.IntegerProperty(indexed=True)
    current_muvs = ndb.IntegerProperty(indexed=False)
    muv_limit = ndb.IntegerProperty(indexed=False)
    status=ndb.StringProperty(indexed=True)
    test_id=ndb.StringProperty(indexed=False)

#let's define page get and post handlers
class MainPage(webapp2.RequestHandler):
    def get(self):
        if "signed_request" in self.request.query_string:
            self.response.set_cookie('signed_request', self.request.query_string)
            context = verify_context(self.request.query_string)
        else:
            context = verify_context(self.request.cookies.get('signed_request'))
        if context != False:
            self.response.write(MAIN_PAGE_TEMPLATE % ("<div>Authenticated!  Go about your business</div>"))

            #deal with tokens and stuff
            token = context['context']['client']['access_token']
            account_id = context['context']['environment']['current_account']

            #check for account_object and create if it doesn't exist
            account = ndb.Key(Account_info, account_id).get()
            if account == None:
                account_info = Account_info()
                account_info.account_id = account_id
                account_info.key = ndb.Key(Account_info, account_id)

            else:
                account_info = account

            account_info.session_token = token
            account_info.put()

        else:
            self.response.write(MAIN_PAGE_TEMPLATE % ("<div>Unauthenticated user, no soup for you!</div>"))


class ConfirmationPage(webapp2.RequestHandler):
    def post(self):
        #create test_info object based on template
        test_info = Test_info()

        #create key for test_info using test_id
        test_info.test_id=self.request.get('test_id')
        test_info.key = ndb.Key(Test_info, test_info.test_id)

        #get account id from context
        context = verify_context(self.request.cookies.get('signed_request'))
        account_id = context['context']['environment']['current_account']

        #get account_id from cookie and set it on test_info object (put happens now so that we can use the session token for the next get request)
        test_info.account_id = account_id
        test_info.put()

        #set api_key and muv_limits based on form input
        test_info.muv_limit=int(self.request.get('muv_limit'))

        #use REST API to lookup current test MUV based on test_id
        set_current_muvs(test_info)

        #use REST API to lookup current test status
        test_info.status = rest_api_get(test_info, "")["status"]

        #create datastore entry
        test_info.put()

        #redirect to load the confirmation page
        query_params = {'test_id':test_info.test_id}
        self.redirect('/confirmation?' + urllib.urlencode(query_params))

    def get(self):
        #get test_id from query param in URL
        test_id = self.request.query_string.split("=")[1]
        test_info = ndb.Key(Test_info, test_id).get()

        #write out confirmation information
        self.response.write(CONFIRMATION_PAGE_TEMPLATE % (test_info.account_id, test_id, test_info.muv_limit, test_info.current_muvs, test_info.status))

class LookupPage(webapp2.RequestHandler):
    def get(self):
        #get account_id from context
        context = verify_context(self.request.cookies.get('signed_request'))
        current_account_id = context['context']['environment']['current_account']

        qry = Test_info.query(Test_info.status == "Running", Test_info.account_id == current_account_id)
        running_tests = qry.fetch()
        formatted_tests = ""
        for test_info in running_tests:
            #use REST API to lookup current test MUV based on test_id
            set_current_muvs(test_info)

            #use REST API to lookup current test status
            test_info.status = rest_api_get(test_info, "")["status"]

            #update datastore entry
            test_info.put()

            #format test_info for printing
            formatted_tests += "Test ID: %s<br>MUV Limit: %s<br>Current Usage: %s<hr>" %(test_info.test_id, str(test_info.muv_limit), str(test_info.current_muvs))


        self.response.write(LOOKUP_PAGE_TEMPLATE % (formatted_tests))


class CronPage(webapp2.RequestHandler):
    def get(self):
        qry = Test_info.query(Test_info.status == "Running")
        running_tests = qry.fetch()
        for test_info in running_tests:

            #use REST API to lookup current test MUV based on test_id
            set_current_muvs(test_info)

            #check if we're over the limit and update the test
            if test_info.current_muvs >= test_info.muv_limit:
                self.response.write(CRON_PAGE_TEMPLATE % ("Time to pause the test"))
                data = {"status":"Paused"}
                response = rest_api_put(test_info, "", data)


                #update the test_info object status
                test_info.status = "Paused"
                test_info.put()

            else:
                self.response.write(CRON_PAGE_TEMPLATE % ("Keep test running until limit is reached"))
                test_info.put()

#let's instantiate the app and define our path mappings
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/confirmation', ConfirmationPage),
    ('/lookup', LookupPage),
    ('/cron', CronPage)
], debug=True)