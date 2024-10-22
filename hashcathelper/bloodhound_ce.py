import requests, json, asyncio, logging

log = logging.getLogger(__name__)

class Sender:
    sessionToken = None
    url = None
    
    def __init__(self, url, sessionToken):
        self.sessionToken = sessionToken
        self.url = url
        
    def run(self, query, users="", edges=""):
        counter = 0
        for user in users:
            data = {
                "query": query.format(user=user),
                "include_properties": True
            }
            
            if self.sendRequest(data) == 200:
                counter += 1
        for edge in edges:
            data = {
                "query": query.format(**edge),
                "include_properties": True
            }
            
            if self.sendRequest(data) == 200:
                counter += 1
        return counter
    
    def sendRequest(self, data):
        # TODO: Error Handling
        return requests.post(url = self.url + "/api/v2/graphs/cypher", json = data, headers={'Authorization': 'Bearer '+self.sessionToken}).status_code
        

class Session:
    driver = None
    sessionToken = None
    
    def __init__(self, driver):
        self.driver = driver
        self.getAuthToken()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exception_type, exception_value, traceback):
        if exception_type:
            if issubclass(exception_type, asyncio.CancelledError):
                self._handle_cancellation(message="__exit__")
                self._closed = True
                return
            self._state_failed = True
    
    def __with__(self):
        with super() as s:
            yield s
        
    def getAuthToken(self):
        data = {
            'login_method':'secret',
            'username':self.driver.username,
            'secret':self.driver.password
        }
        try:
            response = requests.post(url = self.driver.url + "/api/v2/login", json = data)
        except:
            log.error("Cannot connect to %s" % self.driver.url)
            exit(1)
        self.sessionToken = response.json()['data']['session_token']
    
    def write_transaction(
        self,
        transaction_function,
        data):
        return transaction_function(self.sendRequest(), data)
    
    def sendRequest(self):
        return Sender(self.driver.url, self.sessionToken)

class driver:
    url = None
    username = None
    password = None
    
    def __init__(self, url, auth, encrypted=False):
        self.url = url
        self.username = auth[0]
        self.password = auth[1]
        
    def session(self):
        return Session(self)