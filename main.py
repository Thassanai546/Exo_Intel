import os
import requests
import discord
from datetime import datetime
import ipaddress

# VT API
VIRUSTOTAL_API_KEY = os.environ['vt_key']

# Set up Discord bot intents
intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)


# API Hash
def get_vt_hash_info(hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()  # Returns the JSON data from VirusTotal
    else:
        return None


# API IP Address
def get_vt_ip_info(ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()  # Returns the JSON data from VirusTotal
    else:
        return None


# Check for private IP addresses
def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private  # Returns True if the IP is private, False otherwise
    except ValueError:
        return None  # Invalid IP address


# Timestamp display
def format_timestamp(unix_timestamp):
    if unix_timestamp is None or unix_timestamp == 'N/A':
        return 'N/A'
    return datetime.utcfromtimestamp(unix_timestamp).strftime(
        '%Y-%m-%d %H:%M:%S')


@client.event
async def on_ready():
    print('{0.user} is online.'.format(client))


@client.event
async def on_message(message):
    # Ignore messages from the bot itself
    if message.author == client.user:
        return

    # Respond ping test
    if message.content.startswith('/exo'):
        await message.channel.send('Exo Intelligence is online.')

    # Respond to /vt command
    if message.content.startswith('/vt'):
        try:
            input_value = message.content.split(' ')[1]

            # Check if input is an IP address
            if is_private_ip(input_value) is not None:
                if is_private_ip(input_value):
                    await message.channel.send(
                        f"The IP address `{input_value}` is a private IP address and cannot be scanned."
                    )
                else:
                    # Public IP - Call the VirusTotal API for IP addresses
                    vt_ip_info = get_vt_ip_info(input_value)

                    if vt_ip_info:
                        # Extract relevant information from the API response
                        ip_data = vt_ip_info.get('data',
                                                 {}).get('attributes', {})
                        last_analysis_stats = ip_data.get(
                            'last_analysis_stats', {})
                        malicious = last_analysis_stats.get('malicious', 0)
                        total = sum(last_analysis_stats.values())

                        response_msg = f"**Threat Intel for IP:** `{input_value}`\n\n"
                        response_msg += f"**Malicious Detections:** {malicious}/{total}\n"
                        response_msg += f"**Country:** {ip_data.get('country', 'Unknown')}\n"
                        response_msg += f"**Network:** {ip_data.get('network', 'Unknown')}\n"
                        response_msg += f"**ASN:** {ip_data.get('asn', 'Unknown')}\n"

                        # Add a warning if malicious results were found
                        if malicious > 0:
                            response_msg += "\n```⚠️Proceed with caution, malicious activity detected for this IP.```"

                        await message.channel.send(response_msg)
                    else:
                        await message.channel.send(
                            f"Could not retrieve information for IP: `{input_value}`."
                        )
            else:
                # Handle it as a file hash query
                vt_info = get_vt_hash_info(input_value)

                if vt_info:
                    file_info = vt_info.get('data', {}).get('attributes', {})
                    total_scans = file_info.get('last_analysis_stats', {})
                    positives = total_scans.get('malicious', 0)
                    total = sum(total_scans.values())

                    last_scan_date = format_timestamp(
                        file_info.get('last_analysis_date', 'N/A'))
                    first_submission_date = format_timestamp(
                        file_info.get('first_submission_date', 'N/A'))

                    file_size = file_info.get('size', 'Unknown')
                    file_type = file_info.get('type_description', 'Unknown')
                    reputation = file_info.get('reputation', 'N/A')

                    # File signature information
                    signature_info = file_info.get('signature_info', {})
                    signer_name = signature_info.get('signers', ['Unknown'])[0]
                    
                    response_msg = f"**Threat Intel Report for:** `{input_value}`\n\n"
                    response_msg += f"**File Name:** {file_info.get('meaningful_name', 'Unknown')}\n"
                    response_msg += f"**Malicious Detections:** {positives}/{total}\n"
                    response_msg += f"**File Size:** {file_size} bytes\n"
                    response_msg += f"**File Type:** {file_type}\n"
                    response_msg += f"**Reputation Score:** {reputation}\n"
                    response_msg += f"**Last Scan Date:** {last_scan_date}\n"
                    response_msg += f"**First Submission Date:** {first_submission_date}\n"
                    response_msg += f"**SHA256:** {file_info.get('sha256', 'N/A')}\n"
                    response_msg += f"**File Signer:** {signer_name}\n"  # Added signer information

                    if positives > 0:
                        response_msg += "\n```⚠️Proceed with caution, malicious results were found for this value.```"

                    await message.channel.send(response_msg)
                else:
                    await message.channel.send(
                        f"Could not retrieve information for hash: `{input_value}`. Please check if the hash is valid."
                    )
        except IndexError:
            await message.channel.send(
                "Please provide an IP or hash after the `/vt` command. Example: `/vt <ip or hash>`"
            )


try:
    token = os.environ['dscrd_tkn']
    if token == "":
        raise Exception("No Discord Token found.")
    client.run(token)
except discord.HTTPException as e:
    if e.status == 429:
        print(
            "The Discord servers denied the connection for making too many requests"
        )
        print(
            "Get help from https://stackoverflow.com/questions/66724687/in-discord-py-how-to-solve-the-error-for-toomanyrequests"
        )
    else:
        raise e
