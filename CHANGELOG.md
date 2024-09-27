### Version 0.8.0 (2024-09-27)
* Varanus::SSL::CSR - improve support for subclassing
* Varanus::SSL::CSR.generate - support an EC key being passed in

### Version 0.7.1 (2022-01-31)
* Varanus::SSL#certificate_types_standard - also exclude 'Extended Validation'

### Version 0.7.0 (2020-02-03)
* Add Varanus::Domain#report

### Version 0.6.0 (2020-02-01)
* Add Varanus::SSL#report
* Varanus::Reports (Varanus#reports) is now deprecated.

### Version 0.5.1 (2021-01-28)
* Varanus::SSL::CSR - support EC certs

### Version 0.5.0 (2021-01-26)
* Add Varanus::Domain
* Add Varanus::SSL#list and Varanus::SSL#info
* Add Varanus::Organization

### 0.4.0 (2021-01-06)
* Add Varanus::DCV

### 0.3.1 (2020-10-14)
* Fix issue when Sectigo reports two identical 'Short Life' certs

### 0.3.0 (2020-08-24)
* Add support for new 'Short Life' certs

### 0.2.1 (2018-11-13)
* Increase timeout value for SSL requests

### 0.2.0 (2018-11-09)
* Added Varanus::SSL::CSR.generate
* Added Reports
  * Varanus::Reports#ssl - list of SSL/TLS certs
  * Varanus::Reports#domains - list of domains validated with DCV

### 0.1.0 (2018-11-07)
* Initial release
