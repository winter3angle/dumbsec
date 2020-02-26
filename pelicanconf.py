import os


if 'PELICAN_LOCAL_RUN' in os.environ:
    SITEURL = 'http://localhost:8000'
    THEME = '.'
else:
    SITEURL = 'https://dumbsec.ninja'

DEFAULT_CATEGORY = 'misc'
PATH = 'content'
SITENAME = 'Notes from wannabe in everything'
STATIC_PATHS = ['cstatic']
TIMEZONE = 'Europe/Moscow'
AUTHOR = 'Notorious impostor'
THEME_STATIC_PATHS = ['static']
SITESUBTITLE = 'Full-time malware analysis impostor, former software tester and developer'
TAGLINE = SITESUBTITLE
SOCIAL = (('twitter', 'https://twitter.com/no_nuestro'),
          ('github', 'https://github.com/winter3angle'),
          ('h1', 'https://hackerone.com/x268'))
