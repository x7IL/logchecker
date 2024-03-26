import asyncio
import aiohttp


async def geolocate_ip(ip_address):
    geolocation_url = f"https://ipinfo.io/{ip_address}/json"
    timeout = 5  # timeout

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(geolocation_url, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "ip": ip_address,
                        "hostname": data.get("hostname", "N/A"),
                        "city": data.get("city", "N/A"),
                        "region": data.get("region", "N/A"),
                        "country": data.get("country", "N/A"),
                        "loc": data.get("loc", "N/A"),
                        "org": data.get("org", "N/A"),
                        "postal": data.get("postal", "N/A"),
                        "timezone": data.get("timezone", "N/A"),
                    }
                else:
                    return {"error": f"Response status {response.status}"}
        except asyncio.TimeoutError:
            return {"error": "Request timed out"}
        except Exception as e:
            return {"error": str(e)}


# Usage example with 8.8.8.8
ip_address = "76.191.195.140"

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    geolocation_info = loop.run_until_complete(geolocate_ip(ip_address))
    print(geolocation_info)
