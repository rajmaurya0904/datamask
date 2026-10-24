# datamask

**Generate synthetic user datasets and mask the personal data in real CSV, JSON Lines or JSON files, from the command line, for people who test data pipelines.**

Staging databases end up full of real emails because nobody had a clean way to swap them out. Hand-written sed scripts miss columns, and "anonymised" exports quietly keep the original value in a free-text field. datamask finds the columns that look like personal data, masks them with a config you can read, and then checks that the originals did not survive.

```console
$ datamask generate -n 6 --seed 7 --fields first_name,last_name,email,phone,city,dob -o users.csv
$ datamask scan users.csv --write-config mask.toml
users.csv: 6 rows, 6 columns

column      kind        conf  suggested                  why
----------  ----------  ----  -------------------------  ----------------------------------------------
first_name  first_name  0.70  pseudonym:kind=first_name  column name looks like first name
last_name   last_name   0.70  pseudonym:kind=last_name   column name looks like last name
email       email       0.95  pseudonym:kind=email       column name and 100% of values look like email
phone       phone       0.95  partial:keep_last=3        column name and 100% of values look like phone
dob         dob         0.95  date:to=year               column name and 100% of values look like dob

no PII signal: city

5 of 6 columns look like personal data
wrote mask.toml

$ datamask mask users.csv -c mask.toml --salt-file salt.txt -o masked.csv
masked 6 rows -> masked.csv
column      strategy   changed  empty  unparseable
----------  ---------  -------  -----  -----------
first_name  pseudonym  6        0      0
last_name   pseudonym  6        0      0
email       pseudonym  6        0      0
phone       partial    6        0      0
dob         date       6        0      0
left as-is: city

$ cat masked.csv
first_name,last_name,email,phone,city,dob
Zara,Ward,daisy.green9765@mail.example,***** ***609,Cardiff,1962
Omar,Taylor,ella.harris7743@example.org,***** ***574,Edinburgh,1991
Henry,Jones,charlotte.singh5480@inbox.example,***** ***127,Edinburgh,1982
Aisha,Ward,james.singh5298@inbox.example,***** ***010,Sheffield,1990
Oliver,Jackson,noah.singh965@example.org,***** ***853,Cardiff,1945
Grace,Smith,isabelle.singh3475@post.example,***** ***029,Birmingham,1966

$ datamask verify users.csv masked.csv -c mask.toml
checked 5 column(s): first_name, last_name, email, phone, dob
original values checked (per row): 30
cells left unchanged:            0
values reappearing in the row:   0
PASS: no original values found

$ datamask kcheck masked.csv --quasi city -k 2
quasi-identifiers: city
rows: 6   equivalence classes: 4
smallest class (k): 1   unique rows: 2
class sizes (size:count): 1:2  2:2
FAIL: 2 rows in 2 classes are below k=2
```

## Install

Not on PyPI yet, so install from a clone. No runtime dependencies, Python 3.11 or newer.

```bash
pip install -e .
```

## Usage

```bash
datamask generate -n 1000 --seed 1 --locale en,de,fr -o users.csv   # synthetic users, reproducible
datamask scan users.csv --write-config mask.toml                    # find PII columns, write a starter config
datamask mask users.csv -c mask.toml --salt-env DATAMASK_SALT -o out.csv   # apply the rules
datamask verify users.csv out.csv -c mask.toml                      # exit 1 if an original value reappears
```

Rules can also be given inline and repeated, for example `-r phone=partial:keep_last=4 -r notes=scrub`. `datamask strategies` lists the 15 strategies (`redact`, `hash`, `pseudonym`, `date`, `bucket`, `subnet`, `noise`, `shuffle` and so on) with their options. `scan --fail-on-pii` and `kcheck` exit non-zero, so both work as CI gates. Input can be `-` for stdin.

## How it works

- `generate` builds rows from built-in name, address, phone, IBAN and card tables for en, de and fr locales. Card numbers pass Luhn, IBANs pass mod-97, en phone numbers use the UK drama range 07700 900xxx (de and fr numbers are made-up and may belong to real subscribers), and email domains are reserved example domains. A seed makes the output repeatable.
- `scan` scores each column from its header name and from what its values look like (emails, phones, dates, IPs, card numbers that pass Luhn, IBANs and so on) and suggests a strategy per column.
- `mask` applies one strategy per column. `hash` and `pseudonym` are keyed with a secret salt so the same input always gives the same output, which keeps joins between tables working. The salt comes from a file, an environment variable or the config, never the command line.
- Values a strategy cannot handle become empty cells (or abort with `--on-error fail`) and are counted in the summary, so nothing passes through unmasked by accident.
- `verify` compares each masked row with its own original row and reports any original value that is still present, including inside free text. Very common values are skipped, tuned with `--common-threshold`.
- `kcheck` groups rows by quasi-identifier columns and reports the smallest group size.

## Limitations

- Detection is heuristic: header names and value patterns. Personal data in a free-text column with a bland name is only caught if you give that column a `scrub` rule.
- Masked output is not automatically anonymous in the legal sense. Combinations of columns such as city plus birth year can still single people out; `kcheck` measures that for the columns you name, but deciding what is acceptable is up to you. Synthetic data is not a compliance certificate.
- `hash` and `pseudonym` are only as private as the salt. Anyone with the salt and a list of candidate values can reproduce them.
- Name and address tables are small and only cover en, de and fr, so generated datasets repeat surnames and cities at volume.
- Files are read fully into memory. Fine for millions of cells, not for multi-gigabyte exports.

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```

## Licence

MIT, see [LICENSE](LICENSE).
