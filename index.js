const http = require('http');
const request = require('request'); // only direct dependency

// Call chain (project code -> 3rd party lib -> vulnerable function):
//   index.js: fetchWithCookies()
//     -> request (direct)            lib/cookies.js: jar.setCookie()
//       -> tough-cookie@2.5.0 (transitive)   CookieJar.prototype.setCookie()  <- CVE-2023-26136
//
// request's cookie jar is backed by tough-cookie; every response carrying
// Set-Cookie is stored via CookieJar.setCookie().

// Small local server that sets a cookie so the example is self-contained.
const server = http.createServer((req, res) => {
  res.setHeader('Set-Cookie', 'session=abc123; Path=/');
  res.end('ok');
}).listen(3000, () => {
  fetchWithCookies('http://localhost:3000/', () => server.close());
});

function fetchWithCookies(url, done) {
  const jar = request.jar();                 // request -> tough-cookie CookieJar
  jar.setCookie('theme=dark', url);          // request -> tough-cookie CookieJar.setCookie (vulnerable function)
  request({ url, jar }, (err, res, body) => {
    console.log('cookies in jar:', jar.getCookieString(url));
    done();
  });
}
