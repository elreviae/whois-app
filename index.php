<?php
// PHP 8.2 WHOIS Lookup App - Using https://ip-api.com/ free API
// https://ip-api.com/docs/
// Using PHP - CURL library
// Using leaflet JS map - https://leafletjs.com/reference.html

// Maxime DES TOUCHES - https://github.com/elreviae ------------


// Function to validate input type
function validateInput(string $input): ?string {
    $input = trim($input);
    if (empty($input)) return 'myIP';

    // Check if it's an IPv4
    if (filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'ipv4';
    // Check if it's an IPv6
    if (filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'ipv6';
    // Check if it's an email (extract domain)
    if (filter_var($input, FILTER_VALIDATE_EMAIL)) return 'email';
    // Check if it's a domain (basic regex for domain-like strings)
    if (preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $input)) return 'domain';

    return null;
}

// Function to fetch data from API
// Example with JSON data : https://ip-api.com/docs/api:json#test
function fetchWhoisData(string $query): ?array {
    $ch = curl_init('http://ip-api.com/json/'.$query."?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_close($ch);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($curlError) {
        return ['error' => 'cURL Error: ' . $curlError];
    }
    if ($httpCode !== 200) {
        return ['error' => 'HTTP Error: ' . $httpCode . ' - Raw Response: ' . substr($response, 0, 500)];
    }
    if (!$response) {
        return ['error' => 'No response from API'];
    }

    $data = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['error' => 'Invalid JSON Response: ' . json_last_error_msg() . ' - Raw Response: ' . substr($response, 0, 500)];
    }
    // Check for API-specific errors (ipwhois.io returns 'success' and data on success)
    if (isset($data['success']) && !$data['success']) {
        return ['error' => 'API Error: ' . ($data['message'] ?? 'Unknown') . ' - Raw Response: ' . substr($response, 0, 500)];
    }

    return $data;
}

// Handle form submission
$result = null;
$error = null;
$debug = null;
$lat = null;
$lon = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['query'])) {
    $query = htmlspecialchars($_POST['query'], ENT_QUOTES, 'UTF-8');
    $type = validateInput($query);

    if (!$type) {
        $error = 'Invalid input. Please enter a valid domain, IPv4/IPv6 address, or email.';
    } else {
        // For email, extract domain, example : gmail.com
        if ($type === 'email') {
            $query = substr(strrchr($query, '@'), 1);
        }
        $result = fetchWhoisData($query);

        if (isset($result['error'])) {
            $error = $result['error'];
            $debug = $result; // For debugging
        } elseif (!$result) {
            $error = 'Unable to fetch data. Check your input or try again later.';
        } else {
            // Extract lat and lon from JSON data for Leaflet
            $lat = $result['latitude'] ?? $result['lat'] ?? null; // If API uses 'latitude' or 'lat'
            $lon = $result['longitude'] ?? $result['lon'] ?? null; // If API uses 'longitude' or 'lon'
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WHOIS Lookup</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Leaflet CSS -->
     <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
     integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="
     crossorigin=""/>
    <!-- FontAwesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        /* Dark theme overrides */
        pre { color: #ffffff; border: 1px solid #555; padding: 10px; }
        #map { height: 580px; border: 1px solid #555; padding: 10px; }
    </style>
</head>
<body class="bg-dark">

    <div class="container mt-5">

        <h1 class="text-center mb-4 text-light"><i class="fas fa-search"></i> WHOIS Lookup</h1>

        <p class="text-center text-light">Search by domain, IPv4/IPv6 address, or email address. Limited to 45 HTTP requests per minute from an IP address with <a href="https://ip-api.com/" target="_blank">ip-api.com</a></p>

        <!-- Form -->
        <div class="card mb-4 bg-dark border-secondary">
            <div class="card-body">
                <form method="post">
                    <div class="input-group">
                        <input type="text" name="query" class="form-control border-secondary" placeholder="e.g., example.com, 8.8.8.8, user@example.com or leave empty for My IP.">
                        <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i> Lookup</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Error Message -->
        <?php if ($error): ?>
            <div class="alert alert-danger" role="alert">
                <i class="fas fa-exclamation-triangle"></i> <?php echo $error; ?>
            </div>
        <?php endif; ?>

        <!-- Debug Info (only if error) -->
        <?php if ($debug): ?>
            <div class="card mb-4 bg-dark border-secondary">
                <div class="card-header">
                    <h5><i class="fas fa-bug"></i> Debug Info</h5>
                </div>
                <div class="card-body bg-dark border-secondary">
                    <pre><?php echo json_encode($debug, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES); ?></pre>
                </div>
            </div>
        <?php endif; ?>

        <!-- Results -->
        <?php if ($result && !isset($result['error'])): ?>
            <div class="row justify-content-between">

                    <div class="col-6">
                        <div class="card bg-dark border-secondary">
                            <div class="card-header border-secondary text-light">
                                <h5><i class="fas fa-info-circle"></i> WHOIS Results</h5>
                            </div>
                            <div class="card-body bg-dark border-secondary">
                                <pre><?php echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES); ?></pre>
                            </div>
                        </div>
                    </div>
                    
        <?php endif; ?>

        <!-- Map Section -->
        <?php if ($lat !== null && $lon !== null && is_numeric($lat) && is_numeric($lon)): ?>
                    <div class="col-6">
                        <div class="card bg-dark border-secondary">
                            <div class="card-header border-secondary text-light">
                                <h5><i class="fas fa-map-marker-alt"></i> Location Map</h5>
                            </div>
                            <div class="card-body">
                                <div id="map"></div>
                            </div>
                        </div>
                    </div>
        <?php else: ?>
                <div class="alert alert-info" role="alert">
                    <i class="fas fa-info-circle"></i> No location data available for this query.
                </div>
        <?php endif; ?>

            </div>

        
    </div><!-- END container mt-5 -->

      <footer class="footer fixed-bottom">
        <div class="container text-center py-4">
            <span class="text-secondary small">&copy; Maxime DES TOUCHES - <span id="year"></span> | <a target="_blank"
                            href="https://github.com/elreviae" class="text-blue"> <i class="fa-brands fa-github"></i> </a>
            </span> 
        </div>
    </footer>


    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
     <!-- Leaflet JavaScript -->
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
     integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
     crossorigin=""></script>

    <script>
        const d = new Date();
        let year = d.getFullYear();
        document.getElementById("year").innerHTML = year;
    </script>




     <script>
        // initialize the map on the "map" div
        <?php if ($lat !== null && $lon !== null && is_numeric($lat) && is_numeric($lon)): ?>

            var map = L.map('map').setView([<?php echo $lat; ?>, <?php echo $lon; ?>], 10);

            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            }).addTo(map);

            L.marker([<?php echo $lat; ?>, <?php echo $lon; ?>]).addTo(map)
                .bindPopup('Latitude: <?php echo $lat; ?><br>Longitude: <?php echo $lon; ?>')
                .openPopup();

        <?php endif; ?>
     </script>
</body>
</html>
