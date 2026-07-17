# Weather Now — Simple Weather Website

A lightweight, single-file weather website that shows the current conditions and a
7-day forecast for any city. Built with plain HTML, CSS, and JavaScript — no build
step, no framework, no API key required.

## Features

- **Auto-detect location** — uses the browser's geolocation (with permission) to show
  your local weather on page load; falls back to Bengaluru if denied.
- **City search** — look up weather for any city worldwide.
- **Current conditions** — temperature, feels-like, humidity, wind speed, precipitation.
- **7-day forecast** — daily highs/lows with weather icons.
- **Responsive design** — works on phones, tablets, and desktops.
- **Free weather data** — powered by the [Open-Meteo API](https://open-meteo.com/)
  (free for non-commercial use, no API key or signup needed).

## Files

```
weather-website/
├── index.html   ← the entire website (HTML + CSS + JS in one file)
└── README.md
```

## Run locally

Just open `index.html` in a browser. That's it.

> Note: geolocation only works over `https://` or on `localhost`. If you open the
> file directly (`file://`), the site will fall back to the default city — search
> still works fine.

## Deploy to Hostinger

### Option A: File Manager (easiest)

1. Log in to [hPanel](https://hpanel.hostinger.com/).
2. Go to **Websites** → select your website → **File Manager**.
3. Open the `public_html` folder.
4. Delete the placeholder `default.php` / `index.html` if one exists.
5. Upload `index.html` from this folder into `public_html`.
6. Visit your domain — the site is live. (Hostinger provides free SSL, so
   geolocation will work over `https://`.)

### Option B: FTP (FileZilla)

1. In hPanel, go to **Files** → **FTP Accounts** to get your FTP host, username,
   and password.
2. Connect with an FTP client such as [FileZilla](https://filezilla-project.org/).
3. Upload `index.html` into the `public_html` directory.

### Option C: Git deployment

1. In hPanel, go to **Websites** → **Advanced** → **Git**.
2. Add this repository's URL and branch, and set the install path to `public_html`.
3. Note: Hostinger deploys the repo root, so if you use this option you may want to
   move `index.html` to the repo root or point the deployment at this subfolder.

## Customization

- **Default city**: in `index.html`, find `geocodeCity("Bengaluru")` inside the
  `loadDefault()` function and change the city name.
- **Colors**: edit the CSS variables at the top of the `<style>` block
  (`--bg-1`, `--bg-2`, `--accent`, etc.).
- **Units**: Open-Meteo returns Celsius and km/h by default. To switch to
  Fahrenheit/mph, add `&temperature_unit=fahrenheit&wind_speed_unit=mph` to the
  forecast URL in `loadWeather()` and update the `°C`/`km/h` labels.

## Credits

Weather and geocoding data by [Open-Meteo](https://open-meteo.com/), licensed under
CC BY 4.0.
