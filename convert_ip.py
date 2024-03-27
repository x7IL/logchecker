local_networks = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
]


# Function to check if the IP address is within local network ranges
def is_local_ip(ip_address, local_networks):
    # Convert IP address string to an integer
    ip_int = ip_to_int(ip_address)
    print("IP Integer:", ip_int)

    # Check if the IP integer falls within any of the local network ranges
    for start, end in local_networks:
        # Convert start and end IP addresses to integers
        start_int = ip_to_int(start)
        end_int = ip_to_int(end)

        print("Start IP Integer:", start_int)
        print("End IP Integer:", end_int)

        # Check if the IP integer falls within the current network range
        if ip_int >= start_int and ip_int <= end_int:
            return True

    # If IP doesn't belong to any of the local network ranges
    return False


# Function to check if the IP address is within local network ranges
def is_local_ip_optimize(ip_address, local_networks):
    # Convert IP address string to an integer
    ip_int = ip_to_int(ip_address)
    print("IP Integer:", ip_int)

    # Check if the IP integer falls within any of the local network ranges
    return any(
        ip_int >= ip_to_int(start) and ip_int <= ip_to_int(end)
        for start, end in local_networks
    )


def ip_to_int(ip):
    # Split the IP address with dot as a separator
    parts = ip.split(".")

    # Convert each part of the IP address to integer
    part1 = int(parts[0])
    part2 = int(parts[1])
    part3 = int(parts[2])
    part4 = int(parts[3])

    print("Part 1 (before shift):", part1)
    print("Part 2 (before shift):", part2)
    print("Part 3 (before shift):", part3)
    print("Part 4 (before shift):", part4)

    # Left shift each part to its position and combine using bitwise OR
    shifted_part1 = part1 << 24
    shifted_part2 = part2 << 16
    shifted_part3 = part3 << 8

    print("Part 1 (after shift):", shifted_part1)
    print("Part 2 (after shift):", shifted_part2)
    print("Part 3 (after shift):", shifted_part3)

    # Combine shifted parts using bitwise OR
    ip_integer = shifted_part1 | shifted_part2 | shifted_part3 | part4

    print("IP Integer:", ip_integer)

    # Return the resulting integer representing the IP address
    return ip_integer


# Function to convert IP address string to an integer
def ip_to_int_optimize(ip):
    # Séparer l'adresse IP en parties en utilisant le point comme séparateur
    parts = ip.split(".")

    # Première partie : 192
    part1_int = int(parts[0])  # Convertir la première partie en entier
    part1_shifted = part1_int << 24  # Décalage de 24 bits vers la gauche
    print("Partie 1 (après décalage de 24 bits) :", bin(part1_shifted), part1_shifted)

    # Deuxième partie : 168
    part2_int = int(parts[1])  # Convertir la deuxième partie en entier
    part2_shifted = part2_int << 16  # Décalage de 16 bits vers la gauche
    print("Partie 2 (après décalage de 16 bits) :", bin(part2_shifted), part2_shifted)

    # Troisième partie : 5
    part3_int = int(parts[2])  # Convertir la troisième partie en entier
    part3_shifted = part3_int << 8  # Décalage de 8 bits vers la gauche
    print("Partie 3 (après décalage de 8 bits) :", bin(part3_shifted), part3_shifted)

    # Quatrième partie : 4
    part4_int = int(parts[3])  # Convertir la quatrième partie en entier
    print("Partie 4 :", bin(part4_int), part4_int)

    # Combinaison des parties avec l'opérateur OR
    ip_integer = part1_shifted | part2_shifted | part3_shifted | part4_int

    # Retourner l'entier représentant l'adresse IP
    return ip_integer


# print(is_local_ip("145.2.24.14", local_networks))
# print(is_local_ip_optimize("145.2.24.14", local_networks))
print(ip_to_int_optimize("192.164.8.14"))
