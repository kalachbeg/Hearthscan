"""Apple model identifiers ("MacBookPro18,3") and the names Apple sells them under.

Apple devices announce the identifier over mDNS. The ones missing here still get
the family name ("MacBook Pro") from classify.
"""

from __future__ import annotations

_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # iPhone
    ("iPhone 8", ("iPhone10,1", "iPhone10,4")),
    ("iPhone 8 Plus", ("iPhone10,2", "iPhone10,5")),
    ("iPhone X", ("iPhone10,3", "iPhone10,6")),
    ("iPhone XS", ("iPhone11,2",)),
    ("iPhone XS Max", ("iPhone11,4", "iPhone11,6")),
    ("iPhone XR", ("iPhone11,8",)),
    ("iPhone 11", ("iPhone12,1",)),
    ("iPhone 11 Pro", ("iPhone12,3",)),
    ("iPhone 11 Pro Max", ("iPhone12,5",)),
    ("iPhone SE (2nd generation)", ("iPhone12,8",)),
    ("iPhone 12 mini", ("iPhone13,1",)),
    ("iPhone 12", ("iPhone13,2",)),
    ("iPhone 12 Pro", ("iPhone13,3",)),
    ("iPhone 12 Pro Max", ("iPhone13,4",)),
    ("iPhone 13 Pro", ("iPhone14,2",)),
    ("iPhone 13 Pro Max", ("iPhone14,3",)),
    ("iPhone 13 mini", ("iPhone14,4",)),
    ("iPhone 13", ("iPhone14,5",)),
    ("iPhone SE (3rd generation)", ("iPhone14,6",)),
    ("iPhone 14", ("iPhone14,7",)),
    ("iPhone 14 Plus", ("iPhone14,8",)),
    ("iPhone 14 Pro", ("iPhone15,2",)),
    ("iPhone 14 Pro Max", ("iPhone15,3",)),
    ("iPhone 15", ("iPhone15,4",)),
    ("iPhone 15 Plus", ("iPhone15,5",)),
    ("iPhone 15 Pro", ("iPhone16,1",)),
    ("iPhone 15 Pro Max", ("iPhone16,2",)),
    ("iPhone 16 Pro", ("iPhone17,1",)),
    ("iPhone 16 Pro Max", ("iPhone17,2",)),
    ("iPhone 16", ("iPhone17,3",)),
    ("iPhone 16 Plus", ("iPhone17,4",)),
    ("iPhone 16e", ("iPhone17,5",)),
    # iPad
    ("iPad (8th generation)", ("iPad11,6", "iPad11,7")),
    ("iPad (9th generation)", ("iPad12,1", "iPad12,2")),
    ("iPad (10th generation)", ("iPad13,18", "iPad13,19")),
    ("iPad mini (6th generation)", ("iPad14,1", "iPad14,2")),
    ("iPad mini (A17 Pro)", ("iPad16,1", "iPad16,2")),
    ("iPad Air (5th generation)", ("iPad13,16", "iPad13,17")),
    ("iPad Air 11-inch (M2)", ("iPad14,8", "iPad14,9")),
    ("iPad Air 13-inch (M2)", ("iPad14,10", "iPad14,11")),
    ("iPad Pro 11-inch (3rd generation)", ("iPad13,4", "iPad13,5", "iPad13,6", "iPad13,7")),
    ("iPad Pro 12.9-inch (5th generation)", ("iPad13,8", "iPad13,9", "iPad13,10", "iPad13,11")),
    ("iPad Pro 11-inch (4th generation)", ("iPad14,3", "iPad14,4")),
    ("iPad Pro 12.9-inch (6th generation)", ("iPad14,5", "iPad14,6")),
    ("iPad Pro 11-inch (M4)", ("iPad16,3", "iPad16,4")),
    ("iPad Pro 13-inch (M4)", ("iPad16,5", "iPad16,6")),
    # Mac with Intel
    ("Mac mini (2018)", ("Macmini8,1",)),
    ("MacBook Pro (16-inch, 2019)", ("MacBookPro16,1", "MacBookPro16,4")),
    ("MacBook Pro (13-inch, 2020)", ("MacBookPro16,2", "MacBookPro16,3")),
    ("MacBook Air (Retina, 13-inch, 2020)", ("MacBookAir9,1",)),
    ("iMac (Retina 5K, 27-inch, 2020)", ("iMac20,1", "iMac20,2")),
    # Mac with Apple silicon
    ("MacBook Air (M1, 2020)", ("MacBookAir10,1",)),
    ("MacBook Pro (13-inch, M1, 2020)", ("MacBookPro17,1",)),
    ("Mac mini (M1, 2020)", ("Macmini9,1",)),
    ("iMac (24-inch, M1, 2021)", ("iMac21,1", "iMac21,2")),
    ("MacBook Pro (16-inch, 2021)", ("MacBookPro18,1", "MacBookPro18,2")),
    ("MacBook Pro (14-inch, 2021)", ("MacBookPro18,3", "MacBookPro18,4")),
    ("Mac Studio (M1 Max, 2022)", ("Mac13,1",)),
    ("Mac Studio (M1 Ultra, 2022)", ("Mac13,2",)),
    ("MacBook Air (M2, 2022)", ("Mac14,2",)),
    ("MacBook Pro (13-inch, M2, 2022)", ("Mac14,7",)),
    ("Mac mini (M2, 2023)", ("Mac14,3",)),
    ("Mac mini (M2 Pro, 2023)", ("Mac14,12",)),
    ("MacBook Pro (14-inch, 2023)", ("Mac14,5", "Mac14,9")),
    ("MacBook Pro (16-inch, 2023)", ("Mac14,6", "Mac14,10")),
    ("MacBook Air (15-inch, M2, 2023)", ("Mac14,15",)),
    ("Mac Studio (M2 Max, 2023)", ("Mac14,13",)),
    ("Mac Studio (M2 Ultra, 2023)", ("Mac14,14",)),
    ("Mac Pro (2023)", ("Mac14,8",)),
    ("MacBook Pro (14-inch, M3, Nov 2023)", ("Mac15,3",)),
    ("iMac (24-inch, M3, 2023)", ("Mac15,4", "Mac15,5")),
    ("MacBook Pro (14-inch, M3 Pro or M3 Max, Nov 2023)", ("Mac15,6", "Mac15,8", "Mac15,10")),
    ("MacBook Pro (16-inch, Nov 2023)", ("Mac15,7", "Mac15,9", "Mac15,11")),
    ("MacBook Air (13-inch, M3, 2024)", ("Mac15,12",)),
    ("MacBook Air (15-inch, M3, 2024)", ("Mac15,13",)),
    ("Mac Studio (M3 Ultra, 2025)", ("Mac15,14",)),
    ("MacBook Pro (14-inch, M4, 2024)", ("Mac16,1",)),
    ("iMac (24-inch, 2024)", ("Mac16,2", "Mac16,3")),
    ("MacBook Pro (16-inch, 2024)", ("Mac16,5", "Mac16,7")),
    ("MacBook Pro (14-inch, M4 Pro or M4 Max, 2024)", ("Mac16,6", "Mac16,8")),
    ("Mac Studio (M4 Max, 2025)", ("Mac16,9",)),
    ("Mac mini (2024)", ("Mac16,10",)),
    ("Mac mini (M4 Pro, 2024)", ("Mac16,11",)),
    ("MacBook Air (13-inch, M4, 2025)", ("Mac16,12",)),
    ("MacBook Air (15-inch, M4, 2025)", ("Mac16,13",)),
    # TV and speakers
    ("Apple TV HD", ("AppleTV5,3",)),
    ("Apple TV 4K", ("AppleTV6,2",)),
    ("Apple TV 4K (2nd generation)", ("AppleTV11,1",)),
    ("Apple TV 4K (3rd generation)", ("AppleTV14,1",)),
    ("HomePod", ("AudioAccessory1,1", "AudioAccessory1,2")),
    ("HomePod mini", ("AudioAccessory5,1",)),
    ("HomePod (2nd generation)", ("AudioAccessory6,1",)),
)

NAMES: dict[str, str] = {
    identifier.lower(): name for name, identifiers in _GROUPS for identifier in identifiers
}


def identifier(text: str) -> str:
    """'MacBookPro18,3' from 'MacBookPro18,3' or 'MacBookPro18,3@ECOLOR=...'."""
    return text.split("@", 1)[0].strip()


def full_name(text: str) -> str | None:
    """'MacBook Pro (14-inch, 2021)' for 'MacBookPro18,3', None for identifiers not listed."""
    return NAMES.get(identifier(text).lower())
