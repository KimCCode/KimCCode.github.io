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
        }
        else {
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