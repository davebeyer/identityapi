# API Module for the Lighthouse User Identity Server

Used by node.js servers to access the Lighthouse View Labs User Identity server.

For installation instructions, skip down to "Installing."

## Usage

...

## Installing

While only available in private git repository, include in the list of
package.json dependencies like so:

```
"lh-identity" : "https://github.com/davebeyer/identityapi.git"
```

Or:

```
npm install https://github.com/davebeyer/identityapi.git
```

Notes

* Must have access to this private repository on github.com.

* If a permission denied (publickey) error is encountered when
doing "npm install" to install this module from github (such as the
identity module), then you may need to generate and/or add your
computer's public key to the github repository (in Settings/SSH Keys)
as per [these
instructions](https://help.github.com/articles/generating-ssh-keys).

* If you get this error "Cannot read property 'charAt' of undefined",
be sure to update your version of npm if necesssary (should be fixed
in npm >= 2.8.4). 

