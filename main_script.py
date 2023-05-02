# Copyright 2023, John Mueller
# MIT License, see LICENSE file
# SPDX-FileCopyrightText: 2023 John Mueller
# SPDX-License-Identifier: MIT
# https://github.com/softplus/midjourney_lightroom

import os
import re
import uuid
import base64
import dotenv
import hashlib
import requests
import signal
import discord
import piexif
import piexif.helper
from discord.ext import tasks, commands
from urllib.parse import urlencode, quote_plus
from PIL import Image
from lightroom import Lightroom
from io import BytesIO
from datetime import datetime

# folders
dir_root = os.getcwd()
dir_temp = os.path.join(dir_root, "tmp")
dir_output = os.path.join(dir_root, "out")
if not os.path.exists(dir_temp): os.makedirs(dir_temp)
if not os.path.exists(dir_output): os.makedirs(dir_output)

# settings
dotenv_file = dotenv.find_dotenv()
if not dotenv_file: dotenv_file = ".env"
config = dotenv.dotenv_values(dotenv_file)

def config_update(name, value):
    """Update config in dictionary and save to file"""
    global dotenv_file, config
    config[name] = value
    dotenv.set_key(dotenv_file, name, value)

# clean up settings, save as needed

def config_missing(name, default=""):
    global config
    if name not in config: return True
    if config[name] == default: return True

# ask for and save Discord token, if needed
if config_missing("DISCORD_TOKEN", "DISCORD_TOKEN"):
    print("No Discord token found in .env settings. Please create one and enter it now:")
    token = input("Token: ")
    if not token:
        print("No token entered, exiting.")
        quit()
    config_update("DISCORD_TOKEN", token)

# ask for and save Lightroom API client ID and client secret, if needed
if config_missing("LR_CLIENT_ID", "CLIENT_ID"):
    print("No Lightroom API keys found in .env settings. Please create one, and get the client ID + client secret.")
    token = input("Client ID: ")
    if not token:
        print("Nothing entered, exiting.")
        quit()
    config_update("LR_CLIENT_ID", token)
    token = input("Client secret: ")
    if not token:
        print("Nothing entered, exiting.")
        quit()
    config_update("LR_CLIENT_SECRET", token)

# do the salt thing if needed
if config_missing("FILE_SALT", "..."):
    print("Creating new salt for random file names.")
    config_update("FILE_SALT", str(uuid.uuid1()))

# check whether to keep the files
if config_missing("KEEP_FILES"):
    print("Defaulting to keep all files, set KEEP_FILES='0' otherwise")
    config_update("KEEP_FILES", str(1))

def lightroom_login():
    """Attempt to do Lightroom login, return error text if not."""
    global lr_api, lr_catalog, config
    result = ""
    if config_missing("LR_ACCESS_TOKEN"): config["LR_ACCESS_TOKEN"] = ""
    lr_api = Lightroom(config["LR_CLIENT_ID"], config["LR_ACCESS_TOKEN"])
    lr_catalog = None
    try:
        lr_catalog = lr_api.catalog_api()
    except Exception as e:
        result = e
        lr_catalog = None
        lr_api = None
    return result

error_str = lightroom_login()
if error_str:
    print("Lightroom authentication code invalid, starting fresh.")
    print(error_str)

local_channel_id = None
if not config_missing("DISCORD_CHANNEL"): 
    local_channel_id = int(config["DISCORD_CHANNEL"])


# ready to rumble

def exif_date_to_string(in_date):
    """Formate datetime as EXIF date: "YYYY:MM:DD HH:MM:SS"  """
    return in_date.strftime("%Y:%m:%d %H:%M:%S") 


def load_and_split_image(image_file, do_split):
    """split image into 4 equal parts"""
    with Image.open(image_file) as im:
        result = []
        if do_split:
            full_w, full_h = im.size
            part_w = full_w // 2
            part_h = full_h // 2
            result.append(im.crop((0,      0,      part_w, part_h)))
            result.append(im.crop((part_w, 0,      full_w, part_h)))
            result.append(im.crop((0,      part_h, part_w, full_h)))
            result.append(im.crop((part_w, part_h, full_w, full_h)))
        else:
            result.append(im.copy())
        return result


def append_log_csv(data_values):
    """Save values to CSV file for logging"""
    global dir_output
    with open(os.path.join(dir_output, "_log.csv"), "a") as f:
        f.write("\t".join(data_values) + "\n")


def upload_to_form(data_values):
    """Posts list of values to the Google Form."""
    global config
    append_log_csv(data_values)
    if config_missing("FORM_URL", "https://"): return # not set, skipping
    def get_field_ids(form_url):
        """Returns list of field IDs on the form."""
        html = requests.get(form_url).text
        form_field_info = re.findall('(<input|<textarea)[^>]*id="([^"]*)"', html)
        if form_field_info: # depends on UI version
            fields = [x[1] for x in form_field_info if x[1].startswith("entry")]
        else:
            form_field_info = re.findall('\[\[([0-9]{3,30}),null,0\]\]', html)
            fields = ["entry."+x for x in form_field_info]
        return fields
    form_fields = get_field_ids(config["FORM_URL"])
    submit_url = config["FORM_URL"].replace("/viewform", "/formResponse")
    values = {}
    for counter in range(0, min(len(data_values), len(form_fields))):
        values[form_fields[counter]] = data_values[counter]
    data_form = urlencode(values, quote_via=quote_plus)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(submit_url, data=data_form, headers=headers)
    # ignore response


async def process_image_attachment(url, filename, message=None):
    """Do all the things"""
    global config, lr_api, lr_catalog, dir_output
    response = requests.get(url)
    if response.status_code != 200: return

    # save temp image
    input_file = os.path.join(dir_temp, filename)
    with open(input_file, "wb") as f:
        f.write(response.content)
    print(f"  Image downloaded: {filename}")
    file_prefix = os.path.splitext(filename)[0]

    # create metadata for prompt based on message
    infos = {}
    infos["prompt"] = message.content.split("**")[1]
    infos["message_url"] = message.jump_url
    infos["orig_guid"] = filename[-40:-4] # last part of filename before extension
    infos["seed"] = "-1"
    infos["date"] = message.created_at

    images = load_and_split_image(input_file,
                                  do_split=not ("Upscaled by" in message.content 
                                            or " - Image #" in message.content))

    # Save the output images with dynamic names in the output folder
    for index, img in enumerate(images):
        # create new UUID to avoid leaking MJ UUID
        uuid_hash = hashlib.md5((infos["orig_guid"] + str(index) + config["FILE_SALT"]).encode("utf-8"))
        infos["new_guid"] = base64.urlsafe_b64encode(uuid_hash.digest()).decode("utf-8").replace("=","")

        # add exif data with MJ UUID + prompt
        ifd_0 = {
            piexif.ImageIFD.Software: u"Midjourney",
            piexif.ImageIFD.DocumentName: infos["orig_guid"],
            piexif.ImageIFD.ImageDescription: 
                infos["prompt"].encode("latin-1", errors="replace").decode("latin-1"),
            piexif.ImageIFD.DateTime: exif_date_to_string(infos["date"]),
            piexif.ImageIFD.PreviewDateTime: infos["date"].strftime("%Y-%m-%d"),
            piexif.ImageIFD.Model: infos["seed"],
            piexif.ImageIFD.HostComputer: infos["message_url"],
            piexif.ImageIFD.TargetPrinter: infos["new_guid"]
        }
        exif_bytes = piexif.dump({"0th": ifd_0})

        # store locally
        if config["KEEP_FILES"]=="1":
            img.save(os.path.join(dir_output,
                                  f"{file_prefix}_{index}.jpg"),
                                  exif=exif_bytes)
            
        # upload to Lightroom
        try:
            asset_id = lr_catalog.create_new_asset_from_file(
                infos["new_guid"]+".png", "image", 
                capture_date=message.created_at,
                time_stamp=datetime.utcnow())
        except Exception as e: 
            await message.channel.send("Upload to Lightroom failed!")
            await message.channel.send(e)
            return
        
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format="PNG", exif=exif_bytes)
        print(f"  Stored: {infos['new_guid']}.png")
        lr_catalog.put_master(asset_id, img_byte_arr.getvalue(), "image/png")
        upload_to_form([infos["new_guid"], infos["orig_guid"], infos["prompt"], infos["seed"], 
                        infos["message_url"], filename, url, 
                        "https://www.midjourney.com/app?jobId=" + infos["orig_guid"]])
    # Delete the temp file
    os.remove(input_file)


async def lr_auth_ask(channel):
    """Ask the user to authenticate with bounce-page for Lightroom"""
    page_url = "https://lowly-occipital-croissant.glitch.me/"
    authorization_url = "https://ims-na1.adobelogin.com/ims/authorize?"
    params = {
        "client_id" : config["LR_CLIENT_ID"],
        "scope" : "openid,lr_partner_apis,lr_partner_rendition_apis",
        "response_type" : "code",
        "redirect_uri" : page_url
    }
    querystring = urlencode(params, quote_via=quote_plus)
    url = authorization_url + querystring
    await channel.send("Please authenticate here and paste the results here: ")
    await channel.send(url)


async def lr_auth_set(channel, content):
    """Handle Lightroom authentication from user"""
    global lr_api, lr_catalog, config, dotenv_file
    auth_code = content
    if auth_code.startswith("auth! "): auth_code = auth_code[6:]
    # get actual token
    url = "https://ims-na1.adobelogin.com/ims/token"
    params = {
		"grant_type" : "authorization_code",
		"client_id" : config["LR_CLIENT_ID"],
		"client_secret" : config["LR_CLIENT_SECRET"],
		"code" : auth_code
    }
    data_form = urlencode(params, quote_via=quote_plus)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(url, data=data_form, headers=headers)
    access_token = r.json()["access_token"]
    config_update("LR_ACCESS_TOKEN", access_token)
    error_str = lightroom_login()
    if error_str:
        await channel.send("Lightroom authentication is invalid.")
        await channel.send(error_str)
    if not lr_api:
        await lr_auth_ask(channel)
    else:
        await channel.send("Lightroom authentication is ok.")
        lr_catalog = lr_api.catalog_api()


# Basic Discord client
class MyClient(discord.Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


    async def setup_hook(self) -> None:
        # start the task to run in the background
        self.my_background_task.start()


    async def on_ready(self):
        """Discord is ready, say hi"""
        global local_channel_id, lr_api
        print(f'Logged in as {self.user} (ID: {self.user.id})')
        print("Bot connected, enter 'hi!' to confirm")
        if local_channel_id:
            channel = client.get_channel(local_channel_id)
            await channel.send("Your bot Mr_MJ is here.")
            if not lr_api:
                await lr_auth_ask(channel)


    @tasks.loop(seconds=300)  # task runs every X seconds
    async def my_background_task(self):
        """Checks if Lightroom API is still authenticated"""
        global local_channel_id, lr_api
        if not local_channel_id or not lr_api: return

        health = None
        try:
            health = lr_api.health()
        except:
            health = None
        if not health:
            lr_api = None
            channel = client.get_channel(local_channel_id)
            await lr_auth_ask(channel)
        # done


    @my_background_task.before_loop
    async def before_my_task(self):
        """Waits before starting the background loop"""
        await self.wait_until_ready()  # wait until the bot logs in


    #@client.event
    async def on_message(self, message):
        global local_channel_id, lr_api
        print(f"Message: {message.content}")
        if not local_channel_id:
            local_channel_id = message.channel.id
            config_update("DISCORD_CHANNEL", str(local_channel_id))

        # use 'hi!' to check if the bot is around
        if message.content.lower() == "hi!":
            await message.channel.send("Everything ok!")
            if (lr_api):
                await message.channel.send("LR API is ready:")
                await message.channel.send(str(lr_api.account()))
            else:
                await message.channel.send("LR API not connected")
                await lr_auth_ask(message.channel)
            return
        
        # user wants to authenticate, give bounce URL
        if message.content == "auth?":
            await lr_auth_ask(message.channel)

        # user has auth code, process it
        if message.content.startswith("auth! "):
            await lr_auth_set(message.channel, message.content)

        # handle all attachments (the images)
        for attachment in message.attachments:
            #await message.add_reaction("✉️") # you could, but don't

            if attachment.filename.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
                await process_image_attachment(attachment.url, attachment.filename, message)
                print("")

# at this point we start
client = MyClient(intents=discord.Intents.all())
client.run(config["DISCORD_TOKEN"])

# keeps running until you kill it with Ctrl-C/Ctrl-Z
# okbyeeeee
