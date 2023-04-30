# midjourney_lightroom

Pipeline for taking Midjourney images from Discord to Lightroom automatically

This runs as a bot within Discord. It picks up images created by Midjourney, splits preview images into parts, and then adds them all to your Lighthouse CC cloud storage. Drop a bunch of prompts into Discord, receive images in Lighthouse!

(c) 2023 John Mueller, MIT license.
https://github.com/softplus/ & https://johnmu.com/

## setup

```bash
# setup virtualenv -- recommended
virtualenv .venv && source .venv/bin/activate
pip install -r requirements.txt
deactivate
```

## Getting keys

In addition to running this software, you'll need a Lighthouse CC API key and a Discord bot with access keys. Both of these are without extra cost (as far as I know).

Overview of setup:

- Generate Lighthouse CC API keys
- Create a private Discord server
- Create a bot with access keys
- Invite Midjourney and the bot to your private server
- Start the main_script
- Enter the bot key
- Enter the Lighthouse client id & client secret
- Type 'hi!' into Discord to trigger the bot
- Authenticate with Lighthouse for your account (repeat daily)
- Start making images!

## Usage

```bash
source .venv/bin/activate
python3 main_script.py
# ...
```

## Todo

* write readme file
* explain how to get keys
* make google photos version?
* set album via chat command
* auto-do album via prompt, eg "#albumname::0" in prompt
* make sample Google Form
* document bot-making process with screenshots
* document LH-key getting with screenshots
* document authenticating with screenshots

## Done

* include glitch.com HTML + CSS
* test with zero settings
* clean up code
* ask user for auth-codes if needed
* ask for re-auth in chat when needed
* Skip Upscaled images, we have them already
* Test :envelope: reaction -- goes to DM, which sucks
* fetch prompt and save
