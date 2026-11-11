package org.lighttouch.android

import org.junit.Assert.*
import org.junit.Test

class FirmwareSupportTest {
    private fun firmware(id: String, status: String = "experimental", version: String = "3.1.3") =
        id.split('-').let { (board, build) ->
            CatalogFirmware(id, board, "", version, build, "", "", "", 0L, emptyList(), status)
        }

    @Test fun labelsFollowTheCompatibilityRuns() {
        for (id in listOf("n72ap-7E18", "n81ap-10B500", "n88ap-9B206", "n90ap-8L1", "n90ap-10B329", "k48ap-9B206")) {
            assertEquals(id, Support.TESTED, firmware(id).support)
        }
        assertEquals(Support.EXPERIMENTAL, firmware("n90ap-11D257").support)
        assertEquals(Support.UNTESTED, firmware("n90ap-10A403", status = "untested").support)
        // The S5L8900 boards stop at a white screen, whatever the catalog calls them.
        assertEquals(Support.DOESNT_START, firmware("n45ap-4B1").support)
        assertEquals(Support.DOESNT_START, firmware("m68ap-1A543a", status = "untested").support)
        assertFalse(Support.DOESNT_START.tested)
    }

    @Test fun jailbreakAvailabilityMatchesFirmwarekit() {
        assertNull(firmware("n72ap-7E18").jailbreakUnavailable)
        assertTrue(firmware("n72ap-8C148", version = "4.2.1").jailbreakUnavailable!!.contains("iOS 3.1.3"))
        assertNotNull(firmware("n45ap-4A102", version = "1.1.5").jailbreakUnavailable)
        assertNull(firmware("n81ap-10B500", version = "6.1.6").jailbreakUnavailable)
    }
}
