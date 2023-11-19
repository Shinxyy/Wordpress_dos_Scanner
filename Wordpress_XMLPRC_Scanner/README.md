# Wordpress pingback/Dos scanner

The scanner checks wordpress websites and test them out on a few dos/pingback tecniques frequently used in wordpress.

## Dont have poetry installed?
You could easily install poetry with:
```sh
pip install poetry
```

## Installation

Instructions on how to install the project:

```sh
git clone https://github.com/Shinxyy/Wordpress_dos_Scanner.git
cd Wordpress_dos_Scanner/Wordpress_XMLPRC_Scanner
poetry install
```

## Usage
```sh
poetry run python3 xmlrpc_Scanner.py --domains domains.txt --webhook https://webhook.site/{your unique site}
```
