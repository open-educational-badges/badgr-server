import csv
import os
import logging
from typing import List, Optional
from mainsite import TOP_DIR

logger = logging.getLogger(__name__)


class RegionalService:
    """
    Service for managing PLZ (Postal Code) to Landkreis (District) mappings.
    Implements singleton pattern to ensure only one instance loads the CSV data.
    """
    _instance = None
    _plz_data = None
    _landkreis_plz = None
    _plz_to_ort = None  # Maps full PLZ -> Ort (city name)
    _ort_to_plz = None  # Maps Ort (city name) -> Set of PLZ

    @classmethod
    def get_instance(cls):
        """
        Get or create the singleton instance of RegionalService.
        Loads CSV data on first instantiation.

        Returns:
            RegionalService: The singleton instance
        """
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._load_csv()
        return cls._instance

    def _load_csv(self):
        """
        Load PLZ/Landkreis mapping data from CSV file.
        Parses the CSV with delimiter=';' and encoding='utf-8-sig'.
        Caches data in memory for fast lookups.

        Implements defensive error handling:
        - Initializes empty dicts before loading
        - Handles missing CSV file gracefully
        - Handles corrupted CSV data
        - Logs errors for debugging
        """
        # Initialize cache dictionaries first (defensive programming)
        self._plz_data = {}  # Maps PLZ3 -> Landkreis
        self._landkreis_plz = {}  # Maps Landkreis -> Set of PLZ
        self._plz_to_ort = {}  # Maps full PLZ -> Ort (city name)
        self._ort_to_plz = {}  # Maps Ort (city name) -> Set of PLZ

        csv_path = os.path.join(TOP_DIR, "ger_city_zipcode_mapping.csv")

        try:
            if not os.path.exists(csv_path):
                logger.error(
                    f"Regional CSV file not found at {csv_path}. "
                    "Regional filtering will not be available."
                )
                return

            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f, delimiter=';')

                row_count = 0
                for row in reader:
                    try:
                        plz = row.get('PLZ')
                        plz3 = row.get('PLZ3')
                        landkreis = row.get('Landkreis')
                        ort = row.get('Ort')

                        # Skip rows with missing required fields
                        if not all([plz, plz3, landkreis]):
                            logger.warning(
                                f"Skipping row {row_count + 1} with missing data: "
                                f"PLZ={plz}, PLZ3={plz3}, Landkreis={landkreis}"
                            )
                            continue

                        # Cache PLZ3 to Landkreis mapping
                        self._plz_data[plz3] = landkreis

                        # Cache Landkreis to PLZ mapping
                        if landkreis not in self._landkreis_plz:
                            self._landkreis_plz[landkreis] = set()
                        self._landkreis_plz[landkreis].add(plz)

                        # Cache PLZ to Ort mapping
                        if ort:
                            self._plz_to_ort[plz] = ort
                            # Cache Ort to PLZ mapping (reverse lookup)
                            ort_lower = ort.lower()
                            if ort_lower not in self._ort_to_plz:
                                self._ort_to_plz[ort_lower] = set()
                            self._ort_to_plz[ort_lower].add(plz)

                        row_count += 1

                    except Exception as e:
                        logger.warning(
                            f"Error processing CSV row {row_count + 1}: {e}"
                        )
                        continue

                logger.info(
                    f"Successfully loaded {row_count} PLZ/Landkreis mappings "
                    f"from {csv_path}"
                )

        except FileNotFoundError:
            logger.error(
                f"Regional CSV file not found at {csv_path}. "
                "Regional filtering will not be available."
            )
        except PermissionError:
            logger.error(
                f"Permission denied reading CSV file at {csv_path}. "
                "Check file permissions."
            )
        except csv.Error as e:
            logger.error(
                f"CSV parsing error in {csv_path}: {e}. "
                "Regional filtering may be incomplete."
            )
        except Exception as e:
            logger.error(
                f"Unexpected error loading regional CSV from {csv_path}: {e}. "
                "Regional filtering will not be available."
            )

    def get_landkreis_by_plz3(self, plz3: str) -> Optional[str]:
        """
        Get Landkreis (district) name for a given 3-digit PLZ.

        Implements defensive error handling:
        - Handles None input gracefully
        - Handles uninitialized data gracefully
        - Logs warnings for debugging

        Args:
            plz3: 3-digit postal code (e.g., "123")

        Returns:
            str: Landkreis name if found, None otherwise
        """
        if plz3 is None:
            logger.warning("get_landkreis_by_plz3 called with None")
            return None

        if self._plz_data is None:
            logger.warning(
                "PLZ data not initialized. CSV may have failed to load."
            )
            return None

        return self._plz_data.get(plz3)

    def get_all_plz_for_landkreis(self, landkreis: str) -> List[str]:
        """
        Get all postal codes (PLZ) for a given Landkreis.

        Implements defensive error handling:
        - Handles None input gracefully
        - Handles uninitialized data gracefully
        - Logs warnings for debugging

        Args:
            landkreis: Name of the district

        Returns:
            List[str]: List of postal codes, empty list if Landkreis not found
        """
        if landkreis is None:
            logger.warning("get_all_plz_for_landkreis called with None")
            return []

        if self._landkreis_plz is None:
            logger.warning(
                "Landkreis PLZ data not initialized. CSV may have failed to load."
            )
            return []

        return list(self._landkreis_plz.get(landkreis, []))

    def get_all_plz_for_ort(self, ort: str) -> List[str]:
        """
        Get all postal codes (PLZ) for a given Ort (city name).

        Args:
            ort: Name of the city (case-insensitive)

        Returns:
            List[str]: List of postal codes, empty list if Ort not found
        """
        if ort is None:
            logger.warning("get_all_plz_for_ort called with None")
            return []

        if self._ort_to_plz is None:
            logger.warning(
                "Ort to PLZ data not initialized. CSV may have failed to load."
            )
            return []

        return list(self._ort_to_plz.get(ort.lower(), []))

    def get_ort_by_plz(self, plz: str) -> Optional[str]:
        """
        Get Ort (city name) for a given PLZ.

        Args:
            plz: Full postal code (e.g., "80331")

        Returns:
            str: City name if found, None otherwise
        """
        if plz is None:
            return None

        if self._plz_to_ort is None:
            logger.warning(
                "PLZ to Ort data not initialized. CSV may have failed to load."
            )
            return None

        return self._plz_to_ort.get(plz)

    def get_plz3_from_plz(self, plz: str) -> Optional[str]:
        """
        Extract PLZ3 (first 3 digits) from a full PLZ.

        Args:
            plz: Full postal code (e.g., "80331")

        Returns:
            str: First 3 digits of PLZ, None if invalid
        """
        if not plz:
            return None
        # Extract only digits and take first 3
        digits = ''.join(c for c in str(plz) if c.isdigit())
        return digits[:3] if len(digits) >= 3 else None
