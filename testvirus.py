import requests
from bs4 import BeautifulSoup


for i in range(436, 435):

    # URL of the website you want to copy lines from
    url = f"https://virusshare.com/hashfiles/VirusShare_00{i}.md5"
    print(url)

    # Send a GET request to the URL
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content of the page
        soup = BeautifulSoup(response.text, "html.parser")

        # Open a file for writing
        with open("lines.txt", "a") as f:
            # Iterate over all lines in the HTML content
            for line in soup.stripped_strings:
                # Write each line to the file
                f.write(line + "\n")
    else:
        # If the request was not successful, print an error message
        print("Failed to retrieve the content of the website")
