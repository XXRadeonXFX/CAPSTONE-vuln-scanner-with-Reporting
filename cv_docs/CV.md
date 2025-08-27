# CVE Database Integration Setup Guide

## 🚀 Quick Start

### 1. Install Additional Dependencies

```bash
pip install aiohttp asyncio
```

Update your `requirements.txt`:
```
flask
python-dotenv
pymongo
requests
aiohttp
```

### 2. Environment Variables

Add to your `.env` file:
```env
# Existing variables
SLACK_WEBHOOK_URL=your_slack_webhook_url
MONGO_URI=your_mongodb_connection_string

# New CVE integration
NVD_API_KEY=your_nvd_api_key_optional_but_recommended
```

### 3. Get NVD API Key (Recommended)

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Register for a free API key
3. Add it to your `.env` file
4. **Benefits**: Higher rate limits (50 requests/30 seconds vs 5 requests/30 seconds)

## 🎯 Key Features Added

### CVE Database Integration
- **Real-time CVE lookups** from National Vulnerability Database (NVD)
- **Smart caching** (24-hour cache duration to reduce API calls)
- **CVSS score enrichment** (both v2 and v3.1)
- **Reference links** to CVE details and patches
- **CWE mapping** for vulnerability classification

### Enhanced Reporting
- **Risk scoring** based on vulnerability severity
- **Visual risk indicators** in Slack notifications
- **CVE enrichment status** tracking
- **Scanning statistics** endpoint

### Performance Optimizations
- **Async CVE lookups** with concurrency limits
- **MongoDB caching** for CVE data
- **Rate limiting** compliance with NVD guidelines

## 📊 New API Endpoints

### CVE Information
```bash
# Get detailed CVE information
GET /cve/CVE-2021-44228

# Search CVEs (future feature)
GET /cve/search?keyword=docker
```

### Enhanced Scanning
```bash
# Run scan with CVE enrichment (default)
POST /scan?image=nginx:latest&enrich_cve=true

# Run basic scan without CVE data
POST /scan?image=nginx:latest&enrich_cve=false
```

### Statistics
```bash
# Get scanning statistics
GET /stats
```

## 🔧 Configuration Options

### CVE Cache Settings
Modify cache duration in the code:
```python
self.cache_duration = timedelta(hours=24)  # Adjust as needed
```

### Concurrency Limits
Control API request concurrency:
```python
semaphore = asyncio.Semaphore(5)  # Max 5 concurrent requests
```

### Rate Limiting
- **Without API key**: 5 requests per 30 seconds
- **With API key**: 50 requests per 30 seconds

## 🚦 Testing the Integration

### 1. Basic Functionality Test
```bash
# Test CVE lookup
curl "http://localhost:5000/cve/CVE-2021-44228"

# Test enhanced scanning
curl -X POST "http://localhost:5000/scan?image=nginx:1.20&enrich_cve=true"
```

### 2. Verify CVE Enrichment
Look for `cve_details` in vulnerability objects:
```json
{
  "VulnerabilityID": "CVE-2021-44228",
  "Severity": "CRITICAL",
  "cve_details": {
    "id": "CVE-2021-44228",
    "cvss_scores": {
      "v3.1": {
        "score": 10.0,
        "severity": "CRITICAL"
      }
    },
    "references": [...],
    "description": "..."
  }
}
```

### 3. Check Statistics
```bash
curl "http://localhost:5000/stats"
```

## 📈 Monitoring & Observability

### Log Messages to Watch
```
INFO: Using cached CVE data for CVE-2021-44228
INFO: Fetched and cached CVE data for CVE-2021-44228
INFO: Enriching 15 vulnerabilities with CVE data
INFO: CVE enrichment completed
```

### MongoDB Collections
- `reports`: Scan reports with enriched CVE data
- `cve_cache`: Cached CVE information

### Slack Notifications
Enhanced notifications now include:
- 🎯 Risk level indicators
- 🔴🟠🟡🟢 Color-coded severity counts
- ✨ CVE enrichment status

## 🛠️ Troubleshooting

### Common Issues

1. **API Rate Limiting**
   - Solution: Get an NVD API key
   - Monitor logs for rate limit warnings

2. **Slow Scans with CVE Enrichment**
   - Expected behavior for first scan (builds cache)
   - Subsequent scans use cached data

3. **CVE API Timeout**
   - Check network connectivity to NVD
   - Verify API key if using one

4. **Memory Usage**
   - CVE enrichment uses more memory
   - Monitor with large vulnerability counts

### Debug Mode
Run with debug logging:
```python
logging.basicConfig(level=logging.DEBUG)
```

## 🎯 Next Steps

### Immediate Improvements
1. **Test with various Docker images**
2. **Monitor CVE cache hit rates**
3. **Set up Slack webhook for notifications**

### Future Enhancements
1. **CVE search functionality** (keyword-based)
2. **Vulnerability trending** (track changes over time)
3. **Custom CVSS thresholds** for alerts
4. **Integration with MITRE ATT&CK** framework
5. **PDF report generation**

## 📚 Resources

- [NVD API Documentation](https://nvd.nist.gov/developers)
- [CVSS Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
- [CVE Details](https://cvedetails.com/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)

## 🔒 Security Considerations

1. **API Key Security**: Store NVD API key securely
2. **Rate Limiting**: Respect NVD API limits
3. **Data Validation**: Validate CVE data before storage
4. **Cache Expiry**: Don't cache CVE data indefinitely
5. **Error Handling**: Graceful degradation when CVE API is unavailable
