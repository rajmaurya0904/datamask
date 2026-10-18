"""Reference data used to build synthetic people.

Everything here is deliberately small and public-domain-ish: common given names and
surnames, a handful of cities per country, and address / phone / ID formats that are
either reserved for fiction (documentation IP ranges, `.example` domains, Ofcom drama
numbers, never-issued SSN areas) or checksum-valid but not tied to a real person.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Locale:
    code: str
    country: str
    first_names: tuple[str, ...]
    last_names: tuple[str, ...]
    streets: tuple[str, ...]
    cities: tuple[tuple[str, str], ...]  # (city, postcode prefix)
    street_first: bool  # "12 Oak Road" (True) versus "Eichenweg 12" (False)


EN = Locale(
    code="en",
    country="United Kingdom",
    first_names=(
        "Oliver", "George", "Harry", "Jack", "Noah", "Leo", "Arthur", "Oscar", "Charlie",
        "Henry", "Thomas", "William", "James", "Freddie", "Alfie", "Olivia", "Amelia",
        "Isla", "Ava", "Emily", "Sophia", "Grace", "Mia", "Poppy", "Ella", "Lily", "Isabelle",
        "Florence", "Charlotte", "Daisy", "Priya", "Aisha", "Omar", "Rohan", "Zara",
    ),
    last_names=(
        "Smith", "Jones", "Taylor", "Brown", "Williams", "Wilson", "Johnson", "Davies",
        "Robinson", "Wright", "Thompson", "Evans", "Walker", "White", "Roberts", "Green",
        "Hall", "Wood", "Jackson", "Clarke", "Patel", "Khan", "Lewis", "Harris", "Martin",
        "Cooper", "Ward", "Morgan", "Bennett", "Mitchell", "Singh", "Ahmed",
    ),
    streets=(
        "High Street", "Station Road", "Church Lane", "Park Road", "Victoria Road",
        "Green Lane", "Manor Road", "Mill Lane", "The Avenue", "Oak Road", "King Street",
        "Queens Road", "New Road", "Grove Road", "Windsor Close", "Elm Drive",
    ),
    cities=(
        ("London", "EC"), ("Manchester", "M"), ("Birmingham", "B"), ("Leeds", "LS"),
        ("Glasgow", "G"), ("Bristol", "BS"), ("Sheffield", "S"), ("Liverpool", "L"),
        ("Cardiff", "CF"), ("Edinburgh", "EH"), ("Nottingham", "NG"), ("Newcastle", "NE"),
    ),
    street_first=False,
)

DE = Locale(
    code="de",
    country="Germany",
    first_names=(
        "Lukas", "Leon", "Finn", "Jonas", "Paul", "Felix", "Maximilian", "Elias", "Noah",
        "Ben", "Tim", "Jan", "Hannah", "Mia", "Emma", "Sophia", "Lena", "Anna", "Marie",
        "Lea", "Johanna", "Clara", "Laura", "Greta", "Katharina", "Sabine", "Jürgen", "Stefan",
    ),
    last_names=(
        "Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer", "Wagner", "Becker",
        "Schulz", "Hoffmann", "Koch", "Richter", "Klein", "Wolf", "Schröder", "Neumann",
        "Schwarz", "Zimmermann", "Braun", "Krüger", "Hofmann", "Hartmann", "Lange", "Werner",
    ),
    streets=(
        "Hauptstraße", "Bahnhofstraße", "Gartenstraße", "Schulstraße", "Dorfstraße",
        "Birkenweg", "Lindenallee", "Bergstraße", "Kirchplatz", "Waldweg", "Rosenstraße",
        "Eichenweg", "Mozartstraße", "Goethestraße",
    ),
    cities=(
        ("Berlin", "10"), ("Hamburg", "20"), ("München", "80"), ("Köln", "50"),
        ("Frankfurt am Main", "60"), ("Stuttgart", "70"), ("Düsseldorf", "40"),
        ("Leipzig", "04"), ("Dresden", "01"), ("Hannover", "30"), ("Bremen", "28"),
    ),
    street_first=True,
)

FR = Locale(
    code="fr",
    country="France",
    first_names=(
        "Lucas", "Louis", "Hugo", "Gabriel", "Jules", "Arthur", "Raphaël", "Adam", "Nathan",
        "Théo", "Léo", "Émile", "Camille", "Chloé", "Léa", "Manon", "Inès", "Louise", "Jade",
        "Lola", "Zoé", "Alice", "Juliette", "Margaux", "Pierre", "Antoine", "Sophie",
    ),
    last_names=(
        "Martin", "Bernard", "Dubois", "Thomas", "Robert", "Richard", "Petit", "Durand",
        "Leroy", "Moreau", "Simon", "Laurent", "Lefebvre", "Michel", "Garcia", "David",
        "Bertrand", "Roux", "Vincent", "Fournier", "Morel", "Girard", "André", "Mercier",
    ),
    streets=(
        "Rue de la République", "Rue Victor Hugo", "Avenue de la Gare", "Rue des Lilas",
        "Rue Pasteur", "Boulevard Gambetta", "Rue du Moulin", "Place de l'Église",
        "Rue Jean Jaurès", "Chemin des Vignes", "Rue de Verdun", "Impasse des Roses",
    ),
    cities=(
        ("Paris", "75"), ("Marseille", "13"), ("Lyon", "69"), ("Toulouse", "31"),
        ("Nice", "06"), ("Nantes", "44"), ("Strasbourg", "67"), ("Montpellier", "34"),
        ("Bordeaux", "33"), ("Lille", "59"), ("Rennes", "35"),
    ),
    street_first=True,
)

LOCALES: dict[str, Locale] = {loc.code: loc for loc in (EN, DE, FR)}

# Reserved for documentation and fiction, so a generated address can never reach anyone.
EMAIL_DOMAINS = ("mail.example", "inbox.example", "post.example", "example.org", "example.net")

# RFC 5737 (IPv4) documentation ranges.
DOC_IPV4_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")

# Free-text values for "occupation"-style columns, kept short on purpose.
OCCUPATIONS = (
    "Teacher", "Engineer", "Nurse", "Accountant", "Electrician", "Designer", "Developer",
    "Chef", "Solicitor", "Pharmacist", "Carpenter", "Journalist", "Architect", "Driver",
    "Analyst", "Researcher", "Plumber", "Librarian", "Paramedic", "Translator",
)
