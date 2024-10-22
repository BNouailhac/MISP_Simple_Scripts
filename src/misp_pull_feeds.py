import os

# List of feeds
feeds = [
    "https://www.circl.lu/doc/misp/feed-osint/",
    "http://www.botvrij.eu/data/feed-osint/"
]
#   "https://bazaar.abuse.ch/downloads/misp/",
#   "https://urlhaus.abuse.ch/downloads/misp/",
#   "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/",

# Base directory to store downloaded files
base_directory = "./feeds"

def download_files(feed_url, directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
    os.system(f"wget -r -np -nd -A json -P {directory} {feed_url}")

if __name__ == "__main__":
    for feed in feeds:
        feed_name = feed.split("/")[2]
        feed_directory = os.path.join(base_directory, feed_name)
        print(feed_directory)
        download_files(feed, feed_directory)
        print(f"Downloaded files from {feed} to {feed_directory}")