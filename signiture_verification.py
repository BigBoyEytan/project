import os
import subprocess
import re
import datetime
import threading
from pathlib import Path
from typing import Dict, Any, Optional

# Set a timeout for subprocesses (in seconds)
SUBPROCESS_TIMEOUT = 15


class SignatureVerificationEngine:
    """Engine to verify digital signatures of executable files on Windows systems with timeout protection."""

    def __init__(self):
        """Initialize the signature verification engine."""
        pass

    def verify_signature(self, file_path: str) -> Dict[str, Any]:
        """
        Verify the digital signature of a file using Windows authentication mechanisms.

        Args:
            file_path: Path to the file to verify

        Returns:
            Dictionary with signature verification results
        """
        # Create a baseline result with default values
        result = self._create_base_result(file_path)

        try:
            path = Path(file_path)
            if not path.exists() or not path.is_file():
                result["error"] = "File not found"
                return result

            # Check file extension to determine if it's a type that should be signed
            extension = path.suffix.lower()
            signable_extensions = ['.exe', '.dll', '.sys', '.ocx', '.msi', '.ps1', '.psm1', '.cat', '.cab', '.appx']
            result["supports_signing"] = extension in signable_extensions

            # Skip verification for non-signable files
            if not result["supports_signing"]:
                result["error"] = f"File type {extension} does not typically support digital signatures"
                return result

            # Try the simplified verification method with timeout protection
            try:
                print("Starting signature verification...")
                powershell_result = self._run_powershell_with_timeout(file_path)
                if powershell_result["is_signed"]:
                    return powershell_result

                print("PowerShell verification did not find a signature, trying alternative method...")
                # If PowerShell doesn't find a signature, try a simpler approach
                sigcheck_result = self._run_simple_verification(file_path)
                if sigcheck_result["is_signed"]:
                    return sigcheck_result

                # If we get here, no signature was found
                result["error"] = "No digital signature found after trying multiple methods"
                return result

            except TimeoutError:
                result["error"] = "Signature verification timed out after 15 seconds"
                result["verification_failed"] = True
                return result

        except Exception as e:
            result["error"] = f"Verification error: {str(e)}"
            result["verification_failed"] = True
            return result

    def _run_powershell_with_timeout(self, file_path: str) -> Dict[str, Any]:
        """Run PowerShell signature verification with a timeout."""
        result = self._create_base_result(file_path)

        # Use a simple PowerShell command that's less likely to hang
        ps_cmd = f'$sig = Get-AuthenticodeSignature "{file_path}"; ' + \
                 f'$sig.Status; ' + \
                 f'if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject; $sig.SignerCertificate.Issuer }}'

        try:
            # Run PowerShell with timeout
            process = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT
            )

            output = process.stdout
            result["raw_output"] = output

            # Check if we got any output
            if output.strip():
                lines = output.strip().split('\n')

                # First line should be the status
                if len(lines) > 0:
                    status = lines[0].strip()
                    result["is_verified"] = status == "Valid"

                    if status != "NotSigned":
                        result["is_signed"] = True
                        result["signature_exists"] = True

                        # If we have more lines, they should be subject and issuer
                        if len(lines) > 1:
                            subject = lines[1].strip()
                            result["certificate_subject"] = subject

                            # Extract CN from subject
                            cn_match = re.search(r"CN=(.*?)(?:,|$)", subject)
                            if cn_match:
                                result["publisher"] = cn_match.group(1).strip()

                        if len(lines) > 2:
                            result["certificate_issuer"] = lines[2].strip()

                        # Add error info if not verified
                        if not result["is_verified"]:
                            result["error"] = f"Signature verification failed: {status}"
                    else:
                        result["error"] = "File is not signed"
            else:
                result["error"] = "No output from PowerShell verification"

            return result

        except subprocess.TimeoutExpired:
            print("PowerShell verification timed out")
            result["error"] = "PowerShell verification timed out"
            result["verification_failed"] = True
            raise TimeoutError("PowerShell verification timed out")

        except Exception as e:
            print(f"Error in PowerShell verification: {e}")
            result["error"] = f"PowerShell verification error: {str(e)}"
            result["verification_failed"] = True
            return result

    def _run_simple_verification(self, file_path: str) -> Dict[str, Any]:
        """Run a simpler, less detailed signature check."""
        result = self._create_base_result(file_path)

        try:
            # Try a very simplified version of signature checking
            simplified_cmd = f'$result = Get-AuthenticodeSignature "{file_path}" | Select-Object -ExpandProperty Status; Write-Output $result'
            process = subprocess.run(
                ["powershell", "-Command", simplified_cmd],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT
            )

            output = process.stdout.strip()
            result["raw_output"] = output

            if output and output != "NotSigned":
                result["is_signed"] = True
                result["signature_exists"] = True
                result["is_verified"] = output == "Valid"

                if output == "Valid":
                    result["is_trusted"] = True
                else:
                    result["error"] = f"Signature found but status is: {output}"
            else:
                result["error"] = "No signature found with simplified check"

            return result

        except Exception as e:
            result["error"] = f"Simple verification error: {str(e)}"
            return result

    def _create_base_result(self, file_path: str) -> Dict[str, Any]:
        """Create a basic result dictionary with default values."""
        return {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "is_signed": False,
            "is_verified": False,
            "is_trusted": False,
            "signature_exists": False,
            "verification_failed": False,
            "supports_signing": True,
            "publisher": None,
            "certificate_subject": None,
            "certificate_issuer": None,
            "error": None,
            "raw_output": None
        }


