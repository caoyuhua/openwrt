/****************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 * (c) Copyright 2002, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ****************************************************************************

    Module Name:
	cmm_cfg.c

    Abstract:
    Ralink WiFi Driver configuration related subroutines

    Revision History:
    Who          When          What
    ---------    ----------    ----------------------------------------------
*/



#include "rt_config.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#define IWE_STREAM_ADD_EVENT(_A, _B, _C, _D, _E)                iwe_stream_add_event(_A, _B, _C, _D, _E)
#define IWE_STREAM_ADD_POINT(_A, _B, _C, _D, _E)                iwe_stream_add_point(_A, _B, _C, _D, _E)
#define IWE_STREAM_ADD_VALUE(_A, _B, _C, _D, _E, _F)    iwe_stream_add_value(_A, _B, _C, _D, _E, _F)
#else
#define IWE_STREAM_ADD_EVENT(_A, _B, _C, _D, _E)                iwe_stream_add_event(_B, _C, _D, _E)
#define IWE_STREAM_ADD_POINT(_A, _B, _C, _D, _E)                iwe_stream_add_point(_B, _C, _D, _E)
#define IWE_STREAM_ADD_VALUE(_A, _B, _C, _D, _E, _F)    iwe_stream_add_value(_B, _C, _D, _E, _F)
#endif
static BOOLEAN RT_isLegalCmdBeforeInfUp(
       IN PSTRING SetCmd);

static void cal_quality(
        IN RT_CMD_STA_IOCTL_BSS *pSignal,
        IN BSS_ENTRY *pBssEntry)
{
        memcpy(pSignal->Bssid, pBssEntry->Bssid, MAC_ADDR_LEN);

        /* Normalize Rssi */
        if (pBssEntry->Rssi >= -50)
        pSignal->ChannelQuality = 100;
        else if (pBssEntry->Rssi >= -80) /* between -50 ~ -80dbm */
                pSignal->ChannelQuality = (__u8)(24 + ((pBssEntry->Rssi + 80) * 26)/10);
        else if (pBssEntry->Rssi >= -90)   /* between -80 ~ -90dbm */
        pSignal->ChannelQuality = (__u8)((pBssEntry->Rssi + 90) * 26)/10;
        else
                pSignal->ChannelQuality = 0;

    pSignal->Rssi = (__u8)(pBssEntry->Rssi);

    if (pBssEntry->Rssi >= -70)
                pSignal->Noise = -92;
        else
                pSignal->Noise = pBssEntry->Rssi - pBssEntry->MinSNR;
}


static void set_quality(
                        struct iw_quality *iq,
                        RT_CMD_STA_IOCTL_BSS *pBss)
{
        iq->qual = pBss->ChannelQuality;
        iq->level = (__u8)(pBss->Rssi);
        iq->noise = pBss->Noise;


        iq->updated = 1;     /* Flags to know if updated */

#if WIRELESS_EXT >= 17
        iq->updated = IW_QUAL_QUAL_UPDATED | IW_QUAL_LEVEL_UPDATED | IW_QUAL_NOISE_UPDATED;
#endif

#if WIRELESS_EXT >= 19
        iq->updated |= IW_QUAL_DBM;     /* Level + Noise are dBm */
#endif
}

INT
RtmpIoctl_rt_ioctl_giwscan(
        IN      RTMP_ADAPTER                    *pAd,
        IN      VOID                                    *pData,
        IN      ULONG                                   Data)
{
	
        RT_CMD_STA_IOCTL_SCAN_TABLE *pIoctlScan = (RT_CMD_STA_IOCTL_SCAN_TABLE *)pData;
        RT_CMD_STA_IOCTL_BSS_TABLE *pBssTable;
        BSS_ENTRY *pBssEntry;
        UINT32 IdBss;


        pIoctlScan->BssNr = 0;

#ifdef MESH_SUPPORT
        if(pIoctlScan->priv_flags == INT_MESH)
        {
                DBGPRINT(RT_DEBUG_TRACE, ("Mesh do not support rt_ioctl_giwscan \n"));
                        return NDIS_STATUS_FAILURE;
        }

        if (pAd->MeshTab.MeshOnly == TRUE)
                return NDIS_STATUS_SUCCESS;
#endif /* MESH_SUPPORT */

#ifdef WPA_SUPPLICANT_SUPPORT
        if ((pAd->StaCfg.wpa_supplicant_info.WpaSupplicantUP & 0x7F) == WPA_SUPPLICANT_ENABLE)
        {
                pAd->StaCfg.wpa_supplicant_info.WpaSupplicantScanCount = 0;
        }
#endif /* WPA_SUPPLICANT_SUPPORT */

        pIoctlScan->BssNr = pAd->ScanTab.BssNr;
        if (pIoctlScan->BssNr == 0)
                return NDIS_STATUS_SUCCESS;

        os_alloc_mem(NULL, (UCHAR **)&(pIoctlScan->pBssTable),
                                pAd->ScanTab.BssNr * sizeof(RT_CMD_STA_IOCTL_BSS_TABLE));
        if (pIoctlScan->pBssTable == NULL)
        {
                DBGPRINT(RT_DEBUG_ERROR, ("Allocate memory fail!\n"));
                return NDIS_STATUS_FAILURE;
        }

        for(IdBss=0; IdBss<pAd->ScanTab.BssNr; IdBss++)
        {
                HT_CAP_INFO capInfo = pAd->ScanTab.BssEntry[IdBss].HtCapability.HtCapInfo;

                pBssTable = pIoctlScan->pBssTable + IdBss;
                pBssEntry = &pAd->ScanTab.BssEntry[IdBss];
				
                memcpy(pBssTable->Bssid, pBssEntry->Bssid, ETH_ALEN);
                pBssTable->Channel = pBssEntry->Channel;
                pBssTable->BssType = pBssEntry->BssType;
                pBssTable->HtCapabilityLen = pBssEntry->HtCapabilityLen;
                memcpy(pBssTable->SupRate, pBssEntry->SupRate, 12);
                pBssTable->SupRateLen = pBssEntry->SupRateLen;
                memcpy(pBssTable->ExtRate, pBssEntry->ExtRate, 12);
                pBssTable->ExtRateLen = pBssEntry->ExtRateLen;
                pBssTable->SsidLen = pBssEntry->SsidLen;
                memcpy(pBssTable->Ssid, pBssEntry->Ssid, 32);
                pBssTable->CapabilityInfo = pBssEntry->CapabilityInfo;
                pBssTable->ChannelWidth = capInfo.ChannelWidth;
                pBssTable->ShortGIfor40 = capInfo.ShortGIfor40;
                pBssTable->ShortGIfor20 = capInfo.ShortGIfor20;
                pBssTable->MCSSet = pBssEntry->HtCapability.MCSSet[1];
#if defined(CONFIG_STA_SUPPORT) || defined(APCLI_SUPPORT)				
                pBssTable->WpaIeLen = pBssEntry->WpaIE.IELen;
                pBssTable->pWpaIe = pBssEntry->WpaIE.IE;
                pBssTable->RsnIeLen = pBssEntry->RsnIE.IELen;
                pBssTable->pRsnIe = pBssEntry->RsnIE.IE;
#ifdef CONFIG_STA_SUPPORT
                pBssTable->WpsIeLen = pBssEntry->WpsIE.IELen;
                pBssTable->pWpsIe = pBssEntry->WpsIE.IE;
#endif /* CONFIG_STA_SUPPORT */
#endif 
                pBssTable->FlgIsPrivacyOn = CAP_IS_PRIVACY_ON(pBssEntry->CapabilityInfo);
                cal_quality(&pBssTable->Signal, pBssEntry);
        }

        memcpy(pIoctlScan->MainSharedKey[0], pAd->SharedKey[BSS0][0].Key, 16);
        memcpy(pIoctlScan->MainSharedKey[1], pAd->SharedKey[BSS0][1].Key, 16);
        memcpy(pIoctlScan->MainSharedKey[2], pAd->SharedKey[BSS0][2].Key, 16);
        memcpy(pIoctlScan->MainSharedKey[3], pAd->SharedKey[BSS0][3].Key, 16);

        return NDIS_STATUS_SUCCESS;
}

int rt_ioctl_giwscan(struct net_device *dev,
			struct iw_request_info *info,
			struct iw_point *data, char *extra)
{
	VOID *pAd = NULL;
	int i=0, status = 0;
	PSTRING current_ev = extra, previous_ev = extra;
	PSTRING end_buf;
	PSTRING current_val;
	STRING custom[MAX_CUSTOM_LEN] = {0};
#ifndef IWEVGENIE
	unsigned char idx;
#endif /* IWEVGENIE */
	struct iw_event iwe;
	RT_CMD_STA_IOCTL_SCAN_TABLE IoctlScan, *pIoctlScan = &IoctlScan;

	GET_PAD_FROM_NET_DEV(pAd, dev);

	/*check if the interface is down */
/*    if(!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_INTERRUPT_IN_USE)) */
/* because android will set scan and get scan when interface down */
#ifndef ANDROID_SUPPORT
	if (RTMP_DRIVER_IOCTL_SANITY_CHECK(pAd, NULL) != NDIS_STATUS_SUCCESS)
    {
       	DBGPRINT(RT_DEBUG_TRACE, ("INFO::Network is down!\n"));
        return -ENETDOWN;
	}
#endif /* ANDROID_SUPPORT */


	pIoctlScan->priv_flags = RT_DEV_PRIV_FLAGS_GET(dev);
	pIoctlScan->pBssTable = NULL;

#ifdef CONFIG_STA_SUPPORT
	if (RTMP_STA_IoctlHandle(pAd, NULL, CMD_RTPRIV_IOCTL_STA_SIOCGIWSCAN, 0,
							pIoctlScan, 0,
							RT_DEV_PRIV_FLAGS_GET(dev)) != NDIS_STATUS_SUCCESS)
#else
	if (RTMP_AP_IoctlHandle(pAd, NULL, CMD_RTPRIV_IOCTL_AP_SIOCGIWSCAN, 0,
                                                        pIoctlScan,
                                                        RT_DEV_PRIV_FLAGS_GET(dev)) != NDIS_STATUS_SUCCESS)
#endif
	{
		status = -EINVAL;
		goto go_out;
	}

	if (pIoctlScan->BssNr == 0)
	{
		data->length = 0;
		status = 0;
		goto go_out;
	}

#if WIRELESS_EXT >= 17
    if (data->length > 0)
        end_buf = extra + data->length;
    else
        end_buf = extra + IW_SCAN_MAX_DATA;
#else
    end_buf = extra + IW_SCAN_MAX_DATA;
#endif

	for (i = 0; i < pIoctlScan->BssNr; i++) 
	{
		if (current_ev >= end_buf)
        {
#if WIRELESS_EXT >= 17
			status = -E2BIG;
			goto go_out;
#else
			break;
#endif
        }
		
		/*MAC address */
		/*================================ */
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWAP;
		iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
				memcpy(iwe.u.ap_addr.sa_data, &pIoctlScan->pBssTable[i].Bssid, ETH_ALEN);

        previous_ev = current_ev;
		current_ev = IWE_STREAM_ADD_EVENT(info, current_ev,end_buf, &iwe, IW_EV_ADDR_LEN);
        if (current_ev == previous_ev)
        {
#if WIRELESS_EXT >= 17
            status = -E2BIG;
			goto go_out;
#else
			break;
#endif
        }

		/* 
		Protocol:
			it will show scanned AP's WirelessMode .
			it might be
					802.11a
					802.11a/n
					802.11g/n
					802.11b/g/n
					802.11g
					802.11b/g
		*/
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWNAME;


	{
		RT_CMD_STA_IOCTL_BSS_TABLE *pBssEntry=&pIoctlScan->pBssTable[i];
		BOOLEAN isGonly=FALSE;
		int rateCnt=0;

		if (pBssEntry->Channel>14)
		{
			if (pBssEntry->HtCapabilityLen!=0)
				strcpy(iwe.u.name,"802.11a/n");
			else	
				strcpy(iwe.u.name,"802.11a");
		}
		else
		{
			/*
				if one of non B mode rate is set supported rate . it mean G only. 
			*/
			for (rateCnt=0;rateCnt<pBssEntry->SupRateLen;rateCnt++)
			{									
				/*
					6Mbps(140) 9Mbps(146) and >=12Mbps(152) are supported rate , it mean G only. 
				*/
				if (pBssEntry->SupRate[rateCnt]==140 || pBssEntry->SupRate[rateCnt]==146 || pBssEntry->SupRate[rateCnt]>=152)
					isGonly=TRUE;
			}

			for (rateCnt=0;rateCnt<pBssEntry->ExtRateLen;rateCnt++)
			{
				if (pBssEntry->ExtRate[rateCnt]==140 || pBssEntry->ExtRate[rateCnt]==146 || pBssEntry->ExtRate[rateCnt]>=152)
					isGonly=TRUE;
			}		
			
			
			if (pBssEntry->HtCapabilityLen!=0)
			{
				if (isGonly==TRUE)
					strcpy(iwe.u.name,"802.11g/n");
				else
					strcpy(iwe.u.name,"802.11b/g/n");
			}
			else
			{
				if (isGonly==TRUE)
					strcpy(iwe.u.name,"802.11g");
				else
				{
					if (pBssEntry->SupRateLen==4 && pBssEntry->ExtRateLen==0)
						strcpy(iwe.u.name,"802.11b");
					else
						strcpy(iwe.u.name,"802.11b/g");		
				}
			}
		}
	}

		previous_ev = current_ev;
		current_ev = IWE_STREAM_ADD_EVENT(info, current_ev,end_buf, &iwe, IW_EV_ADDR_LEN);
		if (current_ev == previous_ev)
		{
#if WIRELESS_EXT >= 17
	   		status = -E2BIG;
			goto go_out;
#else
			break;
#endif
		}

		/*ESSID */
		/*================================ */
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWESSID;
		iwe.u.data.length = pIoctlScan->pBssTable[i].SsidLen;
		iwe.u.data.flags = 1;
 
        previous_ev = current_ev;
	current_ev = IWE_STREAM_ADD_POINT(info, current_ev,end_buf, &iwe, (PSTRING) pIoctlScan->pBssTable[i].Ssid);
        if (current_ev == previous_ev)
        {
#if WIRELESS_EXT >= 17
            status = -E2BIG;
			goto go_out;
#else
			break;
#endif
        }
		
		/*Network Type */
		/*================================ */
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWMODE;
		if (pIoctlScan->pBssTable[i].BssType == Ndis802_11IBSS)
		{
			iwe.u.mode = IW_MODE_ADHOC;
		}
		else if (pIoctlScan->pBssTable[i].BssType == Ndis802_11Infrastructure)
		{
			iwe.u.mode = IW_MODE_INFRA;
		}
		else
		{
			iwe.u.mode = IW_MODE_AUTO;
		}
		iwe.len = IW_EV_UINT_LEN;

        previous_ev = current_ev;
		current_ev = IWE_STREAM_ADD_EVENT(info, current_ev, end_buf, &iwe,  IW_EV_UINT_LEN);
        if (current_ev == previous_ev)
        {
#if WIRELESS_EXT >= 17
            status = -E2BIG;
			goto go_out;
#else
			break;
#endif
        }

		/*Channel and Frequency */
		/*================================ */
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWFREQ;
		{
			UCHAR ch = pIoctlScan->pBssTable[i].Channel;
			ULONG	m = 0;
#ifdef CONFIG_STA_SUPPORT
			RTMP_STA_IoctlHandle(pAd, NULL, CMD_RTPRIV_IOCTL_CHID_2_FREQ, 0,
								(VOID *)&m, ch, RT_DEV_PRIV_FLAGS_GET(dev));
#else
			MAP_CHANNEL_ID_TO_KHZ(ch, m);
#endif /* CONFIG_STA_SUPPORT */
			iwe.u.freq.m = m * 100;
			iwe.u.freq.e = 1;
			iwe.u.freq.i = ch;
			previous_ev = current_ev;
			current_ev = IWE_STREAM_ADD_EVENT(info, current_ev,end_buf, &iwe, IW_EV_FREQ_LEN);
        		if (current_ev == previous_ev)
	        	{
#if WIRELESS_EXT >= 17
	            		status = -E2BIG;
				goto go_out;
#else
				break;
#endif
			}	    
		}	    

	/*Add quality statistics */
        /*================================ */
        memset(&iwe, 0, sizeof(iwe));
    	iwe.cmd = IWEVQUAL;
    	iwe.u.qual.level = 0;
    	iwe.u.qual.noise = 0;
	set_quality(&iwe.u.qual, &pIoctlScan->pBssTable[i].Signal);
    	current_ev = IWE_STREAM_ADD_EVENT(info, current_ev, end_buf, &iwe, IW_EV_QUAL_LEN);
	if (current_ev == previous_ev)
		{
#if WIRELESS_EXT >= 17
	            status = -E2BIG;
				goto go_out;
#else
			break;
#endif
		}
		/*Encyption key */
		/*================================ */
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWENCODE;
		if (pIoctlScan->pBssTable[i].FlgIsPrivacyOn)
			iwe.u.data.flags =IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
		else
			iwe.u.data.flags = IW_ENCODE_DISABLED;

        previous_ev = current_ev;		
        current_ev = IWE_STREAM_ADD_POINT(info, current_ev, end_buf,&iwe, (char *)pIoctlScan->MainSharedKey[(iwe.u.data.flags & IW_ENCODE_INDEX)-1]);
        if (current_ev == previous_ev)
        {
#if WIRELESS_EXT >= 17
            status = -E2BIG;
			goto go_out;
#else
			break;
#endif
        }

		/*Bit Rate */
		/*================================ */
		if (pIoctlScan->pBssTable[i].SupRateLen)
        {
            UCHAR tmpRate = pIoctlScan->pBssTable[i].SupRate[pIoctlScan->pBssTable[i].SupRateLen-1];
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = SIOCGIWRATE;
    		current_val = current_ev + IW_EV_LCP_LEN;            
            if (tmpRate == 0x82)
                iwe.u.bitrate.value =  1 * 1000000;
            else if (tmpRate == 0x84)
                iwe.u.bitrate.value =  2 * 1000000;
            else if (tmpRate == 0x8B)
                iwe.u.bitrate.value =  5.5 * 1000000;
            else if (tmpRate == 0x96)
                iwe.u.bitrate.value =  11 * 1000000;
            else
    		    iwe.u.bitrate.value =  (tmpRate/2) * 1000000;
            
			if (pIoctlScan->pBssTable[i].ExtRateLen)
			{
				UCHAR tmpSupRate =(pIoctlScan->pBssTable[i].SupRate[pIoctlScan->pBssTable[i].SupRateLen-1]& 0x7f);
				UCHAR tmpExtRate =(pIoctlScan->pBssTable[i].ExtRate[pIoctlScan->pBssTable[i].ExtRateLen-1]& 0x7f);
				iwe.u.bitrate.value = (tmpSupRate > tmpExtRate) ? (tmpSupRate)*500000 : (tmpExtRate)*500000;	
			}

			if (tmpRate == 0x6c && pIoctlScan->pBssTable[i].HtCapabilityLen > 0)
			{
				
/*				HT_CAP_INFO capInfo = pIoctlScan->pBssTable[i].HtCapability.HtCapInfo; */
				int shortGI = pIoctlScan->pBssTable[i].ChannelWidth ? pIoctlScan->pBssTable[i].ShortGIfor40 : pIoctlScan->pBssTable[i].ShortGIfor20;
				//int maxMCS = pIoctlScan->pBssTable[i].MCSSet ?  15 : 7;
				int maxMCS = 7;
#if 1				
				int rate_count = RT_RateSize/sizeof(__s32);
				int rate_index = 12 + ((UCHAR)pIoctlScan->pBssTable[i].ChannelWidth * 24) +
								((UCHAR)shortGI *48) + ((UCHAR)maxMCS);				
				if (rate_index < 0)
					rate_index = 0;
				if (rate_index >= rate_count)
					rate_index = rate_count-1;
				iwe.u.bitrate.value	=  ralinkrate[rate_index] * 500000;
#else

				if (pIoctlScan->pBssTable[i].HtCapabilityLen > 0)
					RtmpDrvRateGet(pAd, MODE_HTMIX, shortGI,
                      pIoctlScan->pBssTable[i].ChannelWidth, maxMCS,
                      newRateGetAntenna(maxMCS), &iwe.u.bitrate.value);
#endif
			}
            
			iwe.u.bitrate.disabled = 0;
			current_val = IWE_STREAM_ADD_VALUE(info, current_ev,
				current_val, end_buf, &iwe,
    			IW_EV_PARAM_LEN);            

        	if((current_val-current_ev)>IW_EV_LCP_LEN)
            	current_ev = current_val;
        	else
        	{
#if WIRELESS_EXT >= 17
                status = -E2BIG;
				goto go_out;
#else
			    break;
#endif
        }
        }

#ifdef IWEVGENIE
        /*WPA IE */
		if (pIoctlScan->pBssTable[i].WpaIeLen > 0)
        {
			memset(&iwe, 0, sizeof(iwe));
			memset(&custom[0], 0, MAX_CUSTOM_LEN);
			memcpy(custom, &(pIoctlScan->pBssTable[i].pWpaIe[0]), 
						   pIoctlScan->pBssTable[i].WpaIeLen);
			iwe.cmd = IWEVGENIE;
			iwe.u.data.length = pIoctlScan->pBssTable[i].WpaIeLen;
			current_ev = IWE_STREAM_ADD_POINT(info, current_ev, end_buf, &iwe, custom);
			if (current_ev == previous_ev)
			{
#if WIRELESS_EXT >= 17
                status = -E2BIG;
				goto go_out;
#else
			    break;
#endif
		}
		}
           
		/*WPA2 IE */
        if (pIoctlScan->pBssTable[i].RsnIeLen > 0)
        {
        	memset(&iwe, 0, sizeof(iwe));
			memset(&custom[0], 0, MAX_CUSTOM_LEN);
			memcpy(custom, &(pIoctlScan->pBssTable[i].pRsnIe[0]), 
						   pIoctlScan->pBssTable[i].RsnIeLen);
			iwe.cmd = IWEVGENIE;
			iwe.u.data.length = pIoctlScan->pBssTable[i].RsnIeLen;
			current_ev = IWE_STREAM_ADD_POINT(info, current_ev, end_buf, &iwe, custom);
			if (current_ev == previous_ev)
			{
#if WIRELESS_EXT >= 17
                status = -E2BIG;
				goto go_out;
#else
			    break;
#endif
        }
        }

#ifdef CONFIG_STA_SUPPORT
		/*WPS IE */
		if (pIoctlScan->pBssTable[i].WpsIeLen > 0)
        {
        	memset(&iwe, 0, sizeof(iwe));
			memset(&custom[0], 0, MAX_CUSTOM_LEN);
			memcpy(custom, &(pIoctlScan->pBssTable[i].pWpsIe[0]), 
						   pIoctlScan->pBssTable[i].WpsIeLen);
			iwe.cmd = IWEVGENIE;
			iwe.u.data.length = pIoctlScan->pBssTable[i].WpsIeLen;
			current_ev = IWE_STREAM_ADD_POINT(info, current_ev, end_buf, &iwe, custom);
			if (current_ev == previous_ev)
			{
#if WIRELESS_EXT >= 17
                status = -E2BIG;
				goto go_out;
#else
			    break;
#endif
        }
        }

#endif
#else
        /*WPA IE */
		/*================================ */
        if (pIoctlScan->pBssTable[i].WpaIeLen > 0)
        {
    		NdisZeroMemory(&iwe, sizeof(iwe));
			memset(&custom[0], 0, MAX_CUSTOM_LEN);
    		iwe.cmd = IWEVCUSTOM;
            iwe.u.data.length = (pIoctlScan->pBssTable[i].WpaIeLen * 2) + 7;
            NdisMoveMemory(custom, "wpa_ie=", 7);
            for (idx = 0; idx < pIoctlScan->pBssTable[i].WpaIeLen; idx++)
                sprintf(custom, "%s%02x", custom, pIoctlScan->pBssTable[i].pWpaIe[idx]);
            previous_ev = current_ev;
    		current_ev = IWE_STREAM_ADD_POINT(info, current_ev, end_buf, &iwe,  custom);
            if (current_ev == previous_ev)
            {
#if WIRELESS_EXT >= 17
                status = -E2BIG;
				goto go_out;
#else
			    break;
#endif
        }
        }

        /*WPA2 IE */
        if (pIoctlScan->pBssTable[i].RsnIeLen > 0)
        {
    		NdisZeroMemory(&iwe, sizeof(iwe));
			memset(&custom[0], 0, MAX_CUSTOM_LEN);
    		iwe.cmd = IWEVCUSTOM;
            iwe.u.data.length = (pIoctlScan->pBssTable[i].RsnIeLen * 2) + 7;
            NdisMoveMemory(custom, "rsn_ie=", 7);
			for (idx = 0; idx < pIoctlScan->pBssTable[i].RsnIeLen; idx++)
                sprintf(custom, "%s%02x", custom, pIoctlScan->pBssTable[i].pRsnIe[idx]);
            previous_ev = current_ev;
    		current_ev = IWE_STREAM_ADD_POINT(info, current_ev, end_buf, &iwe,  custom);
            if (current_ev == previous_ev)
            {
#if WIRELESS_EXT >= 17
                status = -E2BIG;
				goto go_out;
#else
			    break;
#endif
        }
        }

#ifdef WSC_INCLUDED
		/*WPS IE */
		if (pIoctlScan->pBssTable[i].WpsIeLen > 0)
        {
    		NdisZeroMemory(&iwe, sizeof(iwe));
			memset(&custom[0], 0, MAX_CUSTOM_LEN);
    		iwe.cmd = IWEVCUSTOM;
            iwe.u.data.length = (pIoctlScan->pBssTable[i].WpsIeLen * 2) + 7;
            NdisMoveMemory(custom, "wps_ie=", 7);
			for (idx = 0; idx < pIoctlScan->pBssTable[i].WpsIeLen; idx++)
                sprintf(custom, "%s%02x", custom, pIoctlScan->pBssTable[i].pWpsIe[idx]);
            previous_ev = current_ev;
    		current_ev = IWE_STREAM_ADD_POINT(info, current_ev, end_buf, &iwe,  custom);
            if (current_ev == previous_ev)
            {
#if WIRELESS_EXT >= 17
                status = -E2BIG;
				goto go_out;
#else
			    break;
#endif
        }
        }
#endif /* WSC_INCLUDED */

#endif /* IWEVGENIE */
	}

	data->length = current_ev - extra;
/*    pAd->StaCfg.bScanReqIsFromWebUI = FALSE; */
/*	DBGPRINT(RT_DEBUG_ERROR ,("===>rt_ioctl_giwscan. %d(%d) BSS returned, data->length = %d\n",i , pAd->ScanTab.BssNr, data->length)); */

#ifdef CONFIG_STA_SUPPORT
	RTMP_STA_IoctlHandle(pAd, NULL, CMD_RTPRIV_IOCTL_STA_SCAN_END, 0,
						NULL, data->length, RT_DEV_PRIV_FLAGS_GET(dev));
#endif /* CONFIG_STA_SUPPORT */
go_out:
	if (pIoctlScan->pBssTable != NULL)
		os_free_mem(NULL, pIoctlScan->pBssTable);

	return status;
}


INT ComputeChecksum(
	IN UINT PIN)
{
	INT digit_s;
    UINT accum = 0;

	PIN *= 10;
	accum += 3 * ((PIN / 10000000) % 10); 
	accum += 1 * ((PIN / 1000000) % 10); 
	accum += 3 * ((PIN / 100000) % 10); 
	accum += 1 * ((PIN / 10000) % 10); 
	accum += 3 * ((PIN / 1000) % 10); 
	accum += 1 * ((PIN / 100) % 10); 
	accum += 3 * ((PIN / 10) % 10); 

	digit_s = (accum % 10);
	return ((10 - digit_s) % 10);
} /* ComputeChecksum*/

UINT GenerateWpsPinCode(
	IN	PRTMP_ADAPTER	pAd,
    IN  BOOLEAN         bFromApcli,	
	IN	UCHAR			apidx)
{
	UCHAR	macAddr[MAC_ADDR_LEN];
	UINT 	iPin;
	UINT	checksum;

	NdisZeroMemory(macAddr, MAC_ADDR_LEN);

#ifdef CONFIG_AP_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_AP(pAd)
	{
#ifdef APCLI_SUPPORT
	    if (bFromApcli)
	        NdisMoveMemory(&macAddr[0], pAd->ApCfg.ApCliTab[apidx].CurrentAddress, MAC_ADDR_LEN);
	    else
#endif /* APCLI_SUPPORT */
		NdisMoveMemory(&macAddr[0], pAd->ApCfg.MBSSID[apidx].Bssid, MAC_ADDR_LEN);
	}
#endif /* CONFIG_AP_SUPPORT */
#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
		NdisMoveMemory(&macAddr[0], pAd->CurrentAddress, MAC_ADDR_LEN);
#endif /* CONFIG_STA_SUPPORT */

#ifdef P2P_SUPPORT
	if (apidx >= MIN_NET_DEVICE_FOR_P2P_GO)
		NdisMoveMemory(&macAddr[0], pAd->P2PCurrentAddress, MAC_ADDR_LEN);

	if (bFromApcli)
	{
		APCLI_MR_APIDX_SANITY_CHECK(apidx);
		NdisMoveMemory(&macAddr[0], pAd->ApCfg.ApCliTab[apidx].CurrentAddress, MAC_ADDR_LEN);
	}
#endif /* P2P_SUPPORT */
	iPin = macAddr[3] * 256 * 256 + macAddr[4] * 256 + macAddr[5];

	iPin = iPin % 10000000;

	
	checksum = ComputeChecksum( iPin );
	iPin = iPin*10 + checksum;

	return iPin;
}

char* GetPhyMode(
	int Mode)
{
	switch(Mode)
	{
		case MODE_CCK:
			return "CCK";

		case MODE_OFDM:
			return "OFDM";
#ifdef DOT11_N_SUPPORT
		case MODE_HTMIX:
			return "HTMIX";

		case MODE_HTGREENFIELD:
			return "GREEN";
#endif /* DOT11_N_SUPPORT */
		default:
			return "N/A";
	}
}


char* GetBW(
	int BW)
{
	switch(BW)
	{
		case BW_10:
			return "10M";

		case BW_20:
			return "20M";
#ifdef DOT11_N_SUPPORT
		case BW_40:
			return "40M";
#endif /* DOT11_N_SUPPORT */
		default:
			return "N/A";
	}
}


/* 
    ==========================================================================
    Description:
        Set Country Region to pAd->CommonCfg.CountryRegion.
        This command will not work, if the field of CountryRegion in eeprom is programmed.
        
    Return:
        TRUE if all parameters are OK, FALSE otherwise
    ==========================================================================
*/
INT RT_CfgSetCountryRegion(
	IN PRTMP_ADAPTER	pAd, 
	IN PSTRING			arg,
	IN INT				band)
{
	LONG region;
	UCHAR *pCountryRegion;
	
	region = simple_strtol(arg, 0, 10);

	if (band == BAND_24G)
		pCountryRegion = &pAd->CommonCfg.CountryRegion;
	else
		pCountryRegion = &pAd->CommonCfg.CountryRegionForABand;
	
    /*
               1. If this value is set before interface up, do not reject this value.
               2. Country can be set only when EEPROM not programmed
    */
    if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_INTERRUPT_IN_USE) && (*pCountryRegion & EEPROM_IS_PROGRAMMED))
	{
		DBGPRINT(RT_DEBUG_ERROR, ("CfgSetCountryRegion():CountryRegion in eeprom was programmed\n"));
		return FALSE;
	}

	if((region >= 0) && 
	   (((band == BAND_24G) &&((region <= REGION_MAXIMUM_BG_BAND) || 
	   (region == REGION_31_BG_BAND) || (region == REGION_32_BG_BAND) || (region == REGION_33_BG_BAND) )) || 
	    ((band == BAND_5G) && (region <= REGION_MAXIMUM_A_BAND) ))
	  )
	{
		*pCountryRegion= (UCHAR) region;
	}
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("CfgSetCountryRegion():region(%ld) out of range!\n", region));
		return FALSE;
	}

	return TRUE;
	
}


/* 
    ==========================================================================
    Description:
        Set Wireless Mode
    Return:
        TRUE if all parameters are OK, FALSE otherwise
    ==========================================================================
*/
INT RT_CfgSetWirelessMode(
	IN	PRTMP_ADAPTER	pAd, 
	IN	PSTRING			arg)
{
	INT		MaxPhyMode = PHY_11G;
	LONG	WirelessMode;
	
#ifdef DOT11_N_SUPPORT
	if (!RTMP_TEST_MORE_FLAG(pAd, fRTMP_ADAPTER_DISABLE_DOT_11N))
		MaxPhyMode = PHY_11N_5G;
#endif /* DOT11_N_SUPPORT */

	WirelessMode = simple_strtol(arg, 0, 10);

	/* check if chip support 5G band when WirelessMode is 5G band */
	if (PHY_MODE_IS_5G_BAND(WirelessMode))
	{
		if (!RFIC_IS_5G_BAND(pAd))
		{
			DBGPRINT(RT_DEBUG_ERROR,
					("phy mode> Error! The chip does not support 5G band %d!\n",
					pAd->RfIcType));
			return FALSE;
		}
	}

	if (WirelessMode <= MaxPhyMode)
	{
		pAd->CommonCfg.PhyMode = WirelessMode;
		pAd->CommonCfg.DesiredPhyMode = WirelessMode;
		return TRUE;
	}
	
	return FALSE;
	
}


/* maybe can be moved to GPL code, ap_mbss.c, but the code will be open */
#ifdef CONFIG_AP_SUPPORT
#ifdef MBSS_SUPPORT
BOOLEAN RT_CfgMbssWirelessModeSameBand(
	IN	PRTMP_ADAPTER	pAd,
	IN	UCHAR			WirelessModeNew)
{
	BOOLEAN FlgIsOldMode24G = TRUE;
	BOOLEAN FlgIsNewMode24G = TRUE;


	if ((pAd->CommonCfg.PhyMode == PHY_11A)
#ifdef DOT11_N_SUPPORT
		|| (pAd->CommonCfg.PhyMode == PHY_11AN_MIXED)
		|| (pAd->CommonCfg.PhyMode == PHY_11N_5G)
#endif /* DOT11_N_SUPPORT */
		)
	{
		FlgIsOldMode24G = FALSE;
	}

	if ((WirelessModeNew == PHY_11A)
#ifdef DOT11_N_SUPPORT
		|| (WirelessModeNew == PHY_11AN_MIXED)
		|| (WirelessModeNew == PHY_11N_5G)
#endif /* DOT11_N_SUPPORT */
		)
	{
		FlgIsNewMode24G = FALSE;
	}

	DBGPRINT(RT_DEBUG_TRACE,
			("mbss> Old phy mode %d, New phy mode %d!\n",
			pAd->CommonCfg.PhyMode, WirelessModeNew));

	if (FlgIsOldMode24G != FlgIsNewMode24G)
		return FALSE; /* different phy band */

	return TRUE; /* same phy band */
}


UCHAR RT_CfgMbssWirelessModeMaxGet(
	IN	PRTMP_ADAPTER	pAd)
{
	MULTISSID_STRUCT *pMbss;
	UCHAR MaxPhyMode = PHY_11G, WirelessMode;
	UINT32 IdBss;
	BOOLEAN IsAnyB = FALSE; /* any b mode exist */
	BOOLEAN IsAnyG = FALSE; /* any g mode exist */
	BOOLEAN IsAnyA = FALSE; /* any a mode exist */
	BOOLEAN IsAny24N = FALSE; /* any n mode in 2.4G band exist */
	BOOLEAN IsAny5N = FALSE; /* any n mode in 5G band exist */
	BOOLEAN IsAny5 = FALSE; /* any 5G mode */


#ifdef DOT11_N_SUPPORT
	if (!RTMP_TEST_MORE_FLAG(pAd, fRTMP_ADAPTER_DISABLE_DOT_11N))
		MaxPhyMode = PHY_11N_5G;
#endif /* DOT11_N_SUPPORT */

	for(IdBss=0; IdBss<pAd->ApCfg.BssidNum; IdBss++)
	{
		pMbss = &pAd->ApCfg.MBSSID[IdBss];

		/* check if the phy mode is out of range */
		if (pMbss->PhyMode > MaxPhyMode)
			pMbss->PhyMode = PHY_11BG_MIXED; /* default */

		/* check if the phy mode is legal */
		if (pMbss->PhyMode == PHY_11ABG_MIXED)
			pMbss->PhyMode = PHY_11BG_MIXED;

#ifdef DOT11_N_SUPPORT
		if (pMbss->PhyMode == PHY_11ABGN_MIXED)
			pMbss->PhyMode = PHY_11BGN_MIXED;

		if (pMbss->PhyMode == PHY_11AGN_MIXED)
			pMbss->PhyMode = PHY_11GN_MIXED;
#endif /* DOT11_N_SUPPORT */

		/* record the legacy phy mode */
		/*
			Not use array to avoid the value of PHY_11B is changed in the future
			If any code size problem, we can use array to replace if check.
		*/
		if (pMbss->PhyMode == PHY_11B)
			IsAnyB = TRUE;

		if (pMbss->PhyMode == PHY_11G)
			IsAnyG = TRUE;

		if (pMbss->PhyMode == PHY_11BG_MIXED)
		{
			IsAnyB = TRUE;
			IsAnyG = TRUE;
		}

		if (pMbss->PhyMode == PHY_11A)
		{
			IsAnyA = TRUE;
			IsAny5 = TRUE;
		}

#ifdef DOT11_N_SUPPORT
		/* record the N phy mode */
		if (pMbss->PhyMode == PHY_11N_5G)
		{
			IsAny5N = TRUE;
			IsAny5 = TRUE;
		}

		if (pMbss->PhyMode == PHY_11AN_MIXED)
		{
			IsAnyA = TRUE;
			IsAny5N = TRUE;
			IsAny5 = TRUE;
		}

		if (pMbss->PhyMode == PHY_11N_2_4G)
			IsAny24N = TRUE;

		if (pMbss->PhyMode == PHY_11BGN_MIXED)
		{
			IsAnyB = TRUE;
			IsAnyG = TRUE;
			IsAny24N = TRUE;
		}
#endif /* DOT11_N_SUPPORT */
	}

	DBGPRINT(RT_DEBUG_TRACE,
			("mbss> b g a 2.4n 5n %d %d %d %d %d\n",
			IsAnyB, IsAnyG, IsAnyA, IsAny24N, IsAny5N));

	if (IsAny5 == 0)
	{
		if (IsAny24N == 0)
		{
			/* no N phy exists */
			if ((IsAnyB == 1) && (IsAnyG == 1))
				WirelessMode = PHY_11BG_MIXED; /* B & G phy exists */
			else if (IsAnyG == 1)
				WirelessMode = PHY_11G; /* no B phy exists */
			else
				WirelessMode = PHY_11B; /* no G phy exists */
		}
#ifdef DOT11_N_SUPPORT
		else
		{
			/* N phy exists */
			if ((IsAnyB == 1) && (IsAnyG == 1))
				WirelessMode = PHY_11BGN_MIXED; /* B & G phy exists */
			else if (IsAnyG == 1)
				WirelessMode = PHY_11GN_MIXED; /* no B phy exists */
			else
				WirelessMode = PHY_11N_2_4G; /* no G phy exists */
		}
#endif /* DOT11_N_SUPPORT */
	}
	else
	{
		if (IsAny5N == 0)
		{
			/* no N phy exists */
			WirelessMode = PHY_11A; /* A phy exists */
		}
#ifdef DOT11_N_SUPPORT
		else
		{
			/* N phy exists */
			if (IsAnyA == 1)
				WirelessMode = PHY_11AN_MIXED; /* A phy exists */
			else
				WirelessMode = PHY_11N_5G;
		}
#endif /* DOT11_N_SUPPORT */
	} /* End of if */

	DBGPRINT(RT_DEBUG_TRACE, ("mbss> Get WirelessMode = %d\n", WirelessMode));
	return WirelessMode;
}


/* 
    ==========================================================================
    Description:
        Set Wireless Mode for MBSS
    Return:
        TRUE if all parameters are OK, FALSE otherwise
    ==========================================================================
*/
INT RT_CfgSetMbssWirelessMode(
	IN	PRTMP_ADAPTER	pAd, 
	IN	PSTRING			arg)
{
	UINT32	MaxPhyMode = PHY_11G;
	UINT32	WirelessMode;
	
#ifdef DOT11_N_SUPPORT
	if (!RTMP_TEST_MORE_FLAG(pAd, fRTMP_ADAPTER_DISABLE_DOT_11N))
		MaxPhyMode = PHY_11N_5G;
#endif /* DOT11_N_SUPPORT */

	WirelessMode = simple_strtol(arg, 0, 10);

	if ((WirelessMode == PHY_11ABG_MIXED)
#ifdef DOT11_N_SUPPORT
		|| (WirelessMode == PHY_11ABGN_MIXED)
		|| (WirelessMode == PHY_11AGN_MIXED)
#endif /* DOT11_N_SUPPORT */
		)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("mbss> Wrong phy mode for AP!\n"));
		return FALSE;
	}

	/* check if chip support 5G band when WirelessMode is 5G band */
	if (PHY_MODE_IS_5G_BAND(WirelessMode))
	{
		if (!RFIC_IS_5G_BAND(pAd))
		{
			DBGPRINT(RT_DEBUG_ERROR,
					("phy mode> Error! The chip does not support 5G band!\n"));
			return FALSE;
		}
	}

	if (WirelessMode <= MaxPhyMode)
	{
		if (pAd->ApCfg.BssidNum > 1)
		{
			/* pAd->CommonCfg.PhyMode = maximum capability of all MBSS */
			if (RT_CfgMbssWirelessModeSameBand(pAd, WirelessMode) == TRUE)
			{
				WirelessMode = RT_CfgMbssWirelessModeMaxGet(pAd);

				DBGPRINT(RT_DEBUG_TRACE,
						("mbss> Maximum phy mode = %d!\n", WirelessMode));
			}
			else
			{
				UINT32 IdBss;

				/* replace all phy mode with the one with different band */
				DBGPRINT(RT_DEBUG_TRACE,
						("mbss> Different band with the current one!\n"));
				DBGPRINT(RT_DEBUG_TRACE,
						("mbss> Reset band of all BSS to the new one!\n"));

				for(IdBss=0; IdBss<pAd->ApCfg.BssidNum; IdBss++)
					pAd->ApCfg.MBSSID[IdBss].PhyMode = WirelessMode;
			}
		}

		pAd->CommonCfg.PhyMode = WirelessMode;
		pAd->CommonCfg.DesiredPhyMode = WirelessMode;
		return TRUE;
	}
	
	return FALSE;
}
#endif /* MBSS_SUPPORT */
#endif /* CONFIG_AP_SUPPORT */


static BOOLEAN RT_isLegalCmdBeforeInfUp(
       IN PSTRING SetCmd)
{
		BOOLEAN TestFlag;
		TestFlag =	!strcmp(SetCmd, "Debug") ||
#ifdef CONFIG_APSTA_MIXED_SUPPORT
					!strcmp(SetCmd, "OpMode") ||
#endif /* CONFIG_APSTA_MIXED_SUPPORT */
#ifdef EXT_BUILD_CHANNEL_LIST
					!strcmp(SetCmd, "CountryCode") ||
					!strcmp(SetCmd, "DfsType") ||
					!strcmp(SetCmd, "ChannelListAdd") ||
					!strcmp(SetCmd, "ChannelListShow") ||
					!strcmp(SetCmd, "ChannelListDel") ||
#endif /* EXT_BUILD_CHANNEL_LIST */
#ifdef SINGLE_SKU
					!strcmp(SetCmd, "ModuleTxpower") ||
#endif /* SINGLE_SKU */
					FALSE; /* default */
       return TestFlag;
}


INT RT_CfgSetShortSlot(
	IN	PRTMP_ADAPTER	pAd, 
	IN	PSTRING			arg)
{
	LONG ShortSlot;

	ShortSlot = simple_strtol(arg, 0, 10);

	if (ShortSlot == 1)
		pAd->CommonCfg.bUseShortSlotTime = TRUE;
	else if (ShortSlot == 0)
		pAd->CommonCfg.bUseShortSlotTime = FALSE;
	else
		return FALSE;  /*Invalid argument */

	return TRUE;
}


/* 
    ==========================================================================
    Description:
        Set WEP KEY base on KeyIdx
    Return:
        TRUE if all parameters are OK, FALSE otherwise
    ==========================================================================
*/
INT	RT_CfgSetWepKey(
	IN	PRTMP_ADAPTER	pAd, 
	IN	PSTRING			keyString,
	IN	CIPHER_KEY		*pSharedKey,
	IN	INT				keyIdx)
{
	INT				KeyLen;
	INT				i;
	/*UCHAR			CipherAlg = CIPHER_NONE;*/
	BOOLEAN			bKeyIsHex = FALSE;

	/* TODO: Shall we do memset for the original key info??*/
	memset(pSharedKey, 0, sizeof(CIPHER_KEY));
	KeyLen = strlen(keyString);
	switch (KeyLen)
	{
		case 5: /*wep 40 Ascii type*/
		case 13: /*wep 104 Ascii type*/
			bKeyIsHex = FALSE;
			pSharedKey->KeyLen = KeyLen;
			NdisMoveMemory(pSharedKey->Key, keyString, KeyLen);
			break;
			
		case 10: /*wep 40 Hex type*/
		case 26: /*wep 104 Hex type*/
			for(i=0; i < KeyLen; i++)
			{
				if( !isxdigit(*(keyString+i)) )
					return FALSE;  /*Not Hex value;*/
			}
			bKeyIsHex = TRUE;
			pSharedKey->KeyLen = KeyLen/2 ;
			AtoH(keyString, pSharedKey->Key, pSharedKey->KeyLen);
			break;
			
		default: /*Invalid argument */
			DBGPRINT(RT_DEBUG_TRACE, ("RT_CfgSetWepKey(keyIdx=%d):Invalid argument (arg=%s)\n", keyIdx, keyString));
			return FALSE;
	}

	pSharedKey->CipherAlg = ((KeyLen % 5) ? CIPHER_WEP128 : CIPHER_WEP64);
	DBGPRINT(RT_DEBUG_TRACE, ("RT_CfgSetWepKey:(KeyIdx=%d,type=%s, Alg=%s)\n", 
						keyIdx, (bKeyIsHex == FALSE ? "Ascii" : "Hex"), CipherName[pSharedKey->CipherAlg]));

	return TRUE;
}


/* 
    ==========================================================================
    Description:
        Set WPA PSK key

    Arguments:
        pAdapter	Pointer to our adapter
        keyString	WPA pre-shared key string
        pHashStr	String used for password hash function
        hashStrLen	Lenght of the hash string
        pPMKBuf		Output buffer of WPAPSK key

    Return:
        TRUE if all parameters are OK, FALSE otherwise
    ==========================================================================
*/
INT RT_CfgSetWPAPSKKey(
	IN RTMP_ADAPTER	*pAd, 
	IN PSTRING		keyString,
	IN INT			keyStringLen,
	IN UCHAR		*pHashStr,
	IN INT			hashStrLen,
	OUT PUCHAR		pPMKBuf)
{
	UCHAR keyMaterial[40];

	if ((keyStringLen < 8) || (keyStringLen > 64))
	{
		DBGPRINT(RT_DEBUG_TRACE, ("WPAPSK Key length(%d) error, required 8 ~ 64 characters!(keyStr=%s)\n", 
									keyStringLen, keyString));
		return FALSE;
	}

	NdisZeroMemory(pPMKBuf, 32);
	if (keyStringLen == 64)
	{
	    AtoH(keyString, pPMKBuf, 32);
	}
	else
	{
	    RtmpPasswordHash(keyString, pHashStr, hashStrLen, keyMaterial);
	    NdisMoveMemory(pPMKBuf, keyMaterial, 32);		
	}

	return TRUE;
}

INT	RT_CfgSetFixedTxPhyMode(
	IN	PSTRING			arg)
{
	INT		fix_tx_mode = FIXED_TXMODE_HT;
	UINT32	value;

	if (strcmp(arg, "OFDM") == 0 || strcmp(arg, "ofdm") == 0)
	{
		fix_tx_mode = FIXED_TXMODE_OFDM;
	}	
	else if (strcmp(arg, "CCK") == 0 || strcmp(arg, "cck") == 0)
	{
	    fix_tx_mode = FIXED_TXMODE_CCK;
	}
	else if (strcmp(arg, "HT") == 0 || strcmp(arg, "ht") == 0)
	{
	    fix_tx_mode = FIXED_TXMODE_HT;
	}
	else
	{
		value = simple_strtol(arg, 0, 10);
		/* 1 : CCK*/
		/* 2 : OFDM*/
		/* otherwise : HT*/
		if (value == FIXED_TXMODE_CCK || value == FIXED_TXMODE_OFDM)
			fix_tx_mode = value;	
		else
			fix_tx_mode = FIXED_TXMODE_HT;
	}

	return fix_tx_mode;
					
}	

INT	RT_CfgSetMacAddress(
	IN 	PRTMP_ADAPTER 	pAd,
	IN	PSTRING			arg)
{
	INT	i, mac_len;
	
	/* Mac address acceptable format 01:02:03:04:05:06 length 17 */
	mac_len = strlen(arg);
	if(mac_len != 17)  
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s : invalid length (%d)\n", __FUNCTION__, mac_len));
		return FALSE;
	}

	if(strcmp(arg, "00:00:00:00:00:00") == 0)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s : invalid mac setting \n", __FUNCTION__));
		return FALSE;
	}

	for (i = 0; i < MAC_ADDR_LEN; i++)
	{
		AtoH(arg, &pAd->CurrentAddress[i], 1);
		arg = arg + 3;
	}	

	pAd->bLocalAdminMAC = TRUE;
	return TRUE;
}

INT	RT_CfgSetTxMCSProc(
	IN	PSTRING			arg,
	OUT	BOOLEAN			*pAutoRate)
{
	INT	Value = simple_strtol(arg, 0, 10);
	INT	TxMcs;
	
	if ((Value >= 0 && Value <= 23) || (Value == 32)) /* 3*3*/
	{
		TxMcs = Value;
		*pAutoRate = FALSE;
	}
	else
	{		
		TxMcs = MCS_AUTO;
		*pAutoRate = TRUE;
	}

	return TxMcs;

}

INT	RT_CfgSetAutoFallBack(
	IN 	PRTMP_ADAPTER 	pAd,
	IN	PSTRING			arg)
{
	TX_RTY_CFG_STRUC	tx_rty_cfg;
	UCHAR				AutoFallBack = (UCHAR)simple_strtol(arg, 0, 10);

	RTMP_IO_READ32(pAd, TX_RTY_CFG, &tx_rty_cfg.word);
	tx_rty_cfg.field.TxautoFBEnable = (AutoFallBack) ? 1 : 0;
	RTMP_IO_WRITE32(pAd, TX_RTY_CFG, tx_rty_cfg.word);	
	DBGPRINT(RT_DEBUG_TRACE, ("RT_CfgSetAutoFallBack::(tx_rty_cfg=0x%x)\n", tx_rty_cfg.word));
	return TRUE;
}

#ifdef WSC_INCLUDED
INT	RT_CfgSetWscPinCode(
	IN RTMP_ADAPTER *pAd,
	IN PSTRING		pPinCodeStr,
	OUT PWSC_CTRL   pWscControl)
{
	UINT pinCode;

	pinCode = (UINT) simple_strtol(pPinCodeStr, 0, 10); /* When PinCode is 03571361, return value is 3571361.*/
	if (strlen(pPinCodeStr) == 4)
	{
		pWscControl->WscEnrolleePinCode = pinCode;
		pWscControl->WscEnrolleePinCodeLen = 4;
	}
	else if ( ValidateChecksum(pinCode) )
	{
		pWscControl->WscEnrolleePinCode = pinCode;
		pWscControl->WscEnrolleePinCodeLen = 8;
	}
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, ("RT_CfgSetWscPinCode(): invalid Wsc PinCode (%d)\n", pinCode));
		return FALSE;
	}
	
	DBGPRINT(RT_DEBUG_TRACE, ("RT_CfgSetWscPinCode():Wsc PinCode=%d\n", pinCode));
	
	return TRUE;
	
}
#endif /* WSC_INCLUDED */

/*
========================================================================
Routine Description:
	Handler for CMD_RTPRIV_IOCTL_STA_SIOCGIWNAME.

Arguments:
	pAd				- WLAN control block pointer
	*pData			- the communication data pointer
	Data			- the communication data

Return Value:
	NDIS_STATUS_SUCCESS or NDIS_STATUS_FAILURE

Note:
========================================================================
*/
INT RtmpIoctl_rt_ioctl_giwname(
	IN	RTMP_ADAPTER			*pAd,
	IN	VOID					*pData,
	IN	ULONG					Data)
{
#ifdef P2P_SUPPORT
	POS_COOKIE pObj = (POS_COOKIE) pAd->OS_Cookie;
#endif /* P2P_SUPPORT */
	UCHAR CurOpMode = OPMODE_AP;

	if (CurOpMode == OPMODE_AP)
	{
#ifdef P2P_SUPPORT
		if (pObj->ioctl_if_type == INT_P2P)
		{
			if (P2P_CLI_ON(pAd))
				strcpy(pData, "Ralink P2P Cli");
			else if (P2P_GO_ON(pAd))
				strcpy(pData, "Ralink P2P GO");
			else
				strcpy(pData, "Ralink P2P");
		}
		else
#endif /* P2P_SUPPORT */
		strcpy(pData, "RTWIFI SoftAP");
	}

	return NDIS_STATUS_SUCCESS;
}


INT RTMP_COM_IoctlHandle(
	IN	VOID					*pAdSrc,
	IN	RTMP_IOCTL_INPUT_STRUCT	*wrq,
	IN	INT						cmd,
	IN	USHORT					subcmd,
	IN	VOID					*pData,
	IN	ULONG					Data)
{
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER)pAdSrc;
	POS_COOKIE pObj = (POS_COOKIE)pAd->OS_Cookie;
	INT Status = NDIS_STATUS_SUCCESS, i;
	UCHAR PermanentAddress[MAC_ADDR_LEN];
	USHORT Addr01, Addr23, Addr45;


	pObj = pObj; /* avoid compile warning */

	switch(cmd)
	{
		case CMD_RTPRIV_IOCTL_NETDEV_GET:
		/* get main net_dev */
		{
			VOID **ppNetDev = (VOID **)pData;
			*ppNetDev = (VOID *)(pAd->net_dev);
		}
			break;

		case CMD_RTPRIV_IOCTL_NETDEV_SET:
		/* set main net_dev */
			pAd->net_dev = pData;

#ifdef CONFIG_AP_SUPPORT
			pAd->ApCfg.MBSSID[MAIN_MBSSID].MSSIDDev = pData;
#endif /* CONFIG_AP_SUPPORT */
			break;

		case CMD_RTPRIV_IOCTL_OPMODE_GET:
		/* get Operation Mode */
			*(ULONG *)pData = pAd->OpMode;
			break;


		case CMD_RTPRIV_IOCTL_TASK_LIST_GET:
		/* get all Tasks */
		{
			RT_CMD_WAIT_QUEUE_LIST *pList = (RT_CMD_WAIT_QUEUE_LIST *)pData;

			pList->pMlmeTask = &pAd->mlmeTask;
#ifdef RTMP_TIMER_TASK_SUPPORT
			pList->pTimerTask = &pAd->timerTask;
#endif /* RTMP_TIMER_TASK_SUPPORT */
			pList->pCmdQTask = &pAd->cmdQTask;
#ifdef WSC_INCLUDED
			pList->pWscTask = &pAd->wscTask;
#endif /* WSC_INCLUDED */
		}
			break;

		case CMD_RTPRIV_IOCTL_IRQ_INIT:
		/* init IRQ */
			RTMP_IRQ_INIT(pAd);
			break;

		case CMD_RTPRIV_IOCTL_IRQ_RELEASE:
		/* release IRQ */
			RTMP_OS_IRQ_RELEASE(pAd, pAd->net_dev);
			break;

#ifdef RTMP_MAC_PCI
		case CMD_RTPRIV_IOCTL_MSI_ENABLE:
		/* enable MSI */
			RTMP_MSI_ENABLE(pAd);
			*(ULONG **)pData = (ULONG *)(pObj->pci_dev);
			break;
#endif /* RTMP_MAC_PCI */

		case CMD_RTPRIV_IOCTL_NIC_NOT_EXIST:
		/* set driver state to fRTMP_ADAPTER_NIC_NOT_EXIST */
			RTMP_SET_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST);
			break;

#ifdef CONFIG_APSTA_MIXED_SUPPORT
		case CMD_RTPRIV_IOCTL_MAX_IN_BIT:
			/* set MAX_IN_BIT for WMM */
			CW_MAX_IN_BITS = Data;
			break;
#endif /* CONFIG_APSTA_MIXED_SUPPORT */
#ifdef CONFIG_STA_SUPPORT
#ifdef CONFIG_PM
#ifdef USB_SUPPORT_SELECTIVE_SUSPEND
                case CMD_RTPRIV_IOCTL_USB_DEV_GET:
                /* get USB DEV */
                {
                        VOID **ppUsb_Dev = (VOID **)pData;
                        *ppUsb_Dev = (VOID *)(pObj->pUsb_Dev);
                }
                        break;

                case CMD_RTPRIV_IOCTL_USB_INTF_GET:
                /* get USB INTF */
                {
                        VOID **ppINTF = (VOID **)pData;
                        *ppINTF = (VOID *)(pObj->intf);
                }
                        break;

		case CMD_RTPRIV_IOCTL_ADAPTER_SUSPEND_SET:
		/* set driver state to fRTMP_ADAPTER_SUSPEND */
			RTMP_SET_FLAG(pAd,fRTMP_ADAPTER_SUSPEND);
			break;

		case CMD_RTPRIV_IOCTL_ADAPTER_SUSPEND_CLEAR:
		/* clear driver state to fRTMP_ADAPTER_SUSPEND */
			RTMP_CLEAR_FLAG(pAd,fRTMP_ADAPTER_SUSPEND);
			break;

		case CMD_RTPRIV_IOCTL_ADAPTER_SEND_DISSASSOCIATE:
		/* clear driver state to fRTMP_ADAPTER_SUSPEND */
			if (INFRA_ON(pAd) &&
			(!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST)))
			{
				MLME_DISASSOC_REQ_STRUCT	DisReq;
				MLME_QUEUE_ELEM *MsgElem;/* = (MLME_QUEUE_ELEM *) kmalloc(sizeof(MLME_QUEUE_ELEM), MEM_ALLOC_FLAG);*/
				os_alloc_mem(NULL, (UCHAR **)&MsgElem, sizeof(MLME_QUEUE_ELEM));
				if (MsgElem)
				{
					COPY_MAC_ADDR(DisReq.Addr, pAd->CommonCfg.Bssid);
					DisReq.Reason =  REASON_DEAUTH_STA_LEAVING;
					MsgElem->Machine = ASSOC_STATE_MACHINE;
					MsgElem->MsgType = MT2_MLME_DISASSOC_REQ;
					MsgElem->MsgLen = sizeof(MLME_DISASSOC_REQ_STRUCT);
					NdisMoveMemory(MsgElem->Msg, &DisReq, sizeof(MLME_DISASSOC_REQ_STRUCT));
					/* Prevent to connect AP again in STAMlmePeriodicExec*/
					pAd->MlmeAux.AutoReconnectSsidLen= 32;
					NdisZeroMemory(pAd->MlmeAux.AutoReconnectSsid, pAd->MlmeAux.AutoReconnectSsidLen);
					pAd->Mlme.CntlMachine.CurrState = CNTL_WAIT_OID_DISASSOC;
					MlmeDisassocReqAction(pAd, MsgElem);/*				kfree(MsgElem);*/
					os_free_mem(NULL, MsgElem);
				}
				/*				RTMPusecDelay(1000);*/
				RtmpOSWrielessEventSend(pAd->net_dev, RT_WLAN_EVENT_CGIWAP, -1, NULL, NULL, 0);
			}
			break;
			
		case CMD_RTPRIV_IOCTL_ADAPTER_SUSPEND_TEST:
		/* test driver state to fRTMP_ADAPTER_SUSPEND */
			*(UCHAR *)pData = RTMP_TEST_FLAG(pAd,fRTMP_ADAPTER_SUSPEND);
			break;

		case CMD_RTPRIV_IOCTL_ADAPTER_IDLE_RADIO_OFF_TEST:
		/* test driver state to fRTMP_ADAPTER_IDLE_RADIO_OFF */
			*(UCHAR *)pData = RTMP_TEST_FLAG(pAd,fRTMP_ADAPTER_IDLE_RADIO_OFF);
			break;

		case CMD_RTPRIV_IOCTL_ADAPTER_RT28XX_USB_ASICRADIO_OFF:
		/* RT28xxUsbAsicRadioOff */
			RT28xxUsbAsicRadioOff(pAd);
			break;

		case CMD_RTPRIV_IOCTL_ADAPTER_RT28XX_USB_ASICRADIO_ON:
		/* RT28xxUsbAsicRadioOn */
			RT28xxUsbAsicRadioOn(pAd);
			break;

#ifdef WOW_SUPPORT
#endif /* WOW_SUPPORT */

#endif /* USB_SUPPORT_SELECTIVE_SUSPEND */
#endif /* CONFIG_PM */	

		case CMD_RTPRIV_IOCTL_AP_BSSID_GET:
			if (pAd->StaCfg.PortSecured == WPA_802_1X_PORT_NOT_SECURED)
				NdisCopyMemory(pData, pAd->MlmeAux.Bssid, 6);
			else
				return NDIS_STATUS_FAILURE;
			break;
#endif /* CONFIG_STA_SUPPORT */

		case CMD_RTPRIV_IOCTL_SANITY_CHECK:
		/* sanity check before IOCTL */
			if ((!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_INTERRUPT_IN_USE))
#ifdef IFUP_IN_PROBE
			|| (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_RESET_IN_PROGRESS))
			|| (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS))
			|| (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST))
#endif /* IFUP_IN_PROBE */
			)
			{
				if(pData == NULL ||	RT_isLegalCmdBeforeInfUp((PSTRING) pData) == FALSE)
				return NDIS_STATUS_FAILURE;
			}
			break;

		case CMD_RTPRIV_IOCTL_SIOCGIWFREQ:
		/* get channel number */
			*(ULONG *)pData = pAd->CommonCfg.Channel;
			break;
		case CMD_RTPRIV_IOCTL_SIOCGIWHWMODE:
			*(ULONG *)pData = pAd->ApCfg.MBSSID[0].PhyMode;
			break;
		case CMD_RTPRIV_IOCTL_AP_SIOCGIWTXPOW:
			if (pAd->CommonCfg.TxPowerPercentage >= 90)
			{
				*(ULONG *)pData = 15;
			}
			else if (pAd->CommonCfg.TxPowerPercentage >= 60)
			{
				*(ULONG *)pData = 14;
			}
			else if (pAd->CommonCfg.TxPowerPercentage >= 30)
			{
				*(ULONG *)pData = 12;
			}
			else if (pAd->CommonCfg.TxPowerPercentage >= 15)
			{
				*(ULONG *)pData = 9;
			}
			else if (pAd->CommonCfg.TxPowerPercentage >= 0)
			{
				*(ULONG *)pData = 6;
			}
			break;


#ifdef P2P_SUPPORT
		case CMD_RTPRIV_IOCTL_P2P_INIT:
			P2pInit(pAd, pData);
			break;

		case CMD_RTPRIV_IOCTL_P2P_REMOVE:
			P2P_Remove(pAd);
			break;

		case CMD_RTPRIV_IOCTL_P2P_OPEN_PRE:
			if (P2P_OpenPre(pData) != 0)
				return NDIS_STATUS_FAILURE;
			break;

		case CMD_RTPRIV_IOCTL_P2P_OPEN_POST:
			if (P2P_OpenPost(pData) != 0)
				return NDIS_STATUS_FAILURE;
			break;

		case CMD_RTPRIV_IOCTL_P2P_CLOSE:
			P2P_Close(pData);
			break;
#endif /* P2P_SUPPORT */

		case CMD_RTPRIV_IOCTL_BEACON_UPDATE:
		/* update all beacon contents */
#ifdef CONFIG_AP_SUPPORT
			APMakeAllBssBeacon(pAd);
			APUpdateAllBeaconFrame(pAd);
#endif /* CONFIG_AP_SUPPORT */
			break;

		case CMD_RTPRIV_IOCTL_RXPATH_GET:
		/* get the number of rx path */
			*(ULONG *)pData = pAd->Antenna.field.RxPath;
			break;

		case CMD_RTPRIV_IOCTL_CHAN_LIST_NUM_GET:
			*(ULONG *)pData = pAd->ChannelListNum;
			break;

		case CMD_RTPRIV_IOCTL_CHAN_LIST_GET:
		{
			UINT32 i;
			UCHAR *pChannel = (UCHAR *)pData;

			for (i = 1; i <= pAd->ChannelListNum; i++)
			{
				*pChannel = pAd->ChannelList[i-1].Channel;
				pChannel ++;
			}
		}
			break;

		case CMD_RTPRIV_IOCTL_FREQ_LIST_GET:
		{
			UINT32 i;
			UINT32 *pFreq = (UINT32 *)pData;
			UINT32 m;

			for (i = 1; i <= pAd->ChannelListNum; i++)
			{
				m = 2412000;
				MAP_CHANNEL_ID_TO_KHZ(pAd->ChannelList[i-1].Channel, m);
				(*pFreq) = m;
				pFreq ++;
			}
		}
			break;

#ifdef EXT_BUILD_CHANNEL_LIST
       case CMD_RTPRIV_SET_PRECONFIG_VALUE:
       /* Set some preconfigured value before interface up*/
           pAd->CommonCfg.DfsType = MAX_RD_REGION;
           break;
#endif /* EXT_BUILD_CHANNEL_LIST */



#ifdef RTMP_PCI_SUPPORT
		case CMD_RTPRIV_IOCTL_PCI_SUSPEND:
			RTMP_SET_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS);
			RTMP_SET_FLAG(pAd, fRTMP_ADAPTER_RADIO_OFF);
			break;

		case CMD_RTPRIV_IOCTL_PCI_RESUME:
			RTMP_CLEAR_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS);
			RTMP_CLEAR_FLAG(pAd, fRTMP_ADAPTER_RADIO_OFF);
			break;

		case CMD_RTPRIV_IOCTL_PCI_CSR_SET:
			pAd->CSRBaseAddress = (PUCHAR)Data;
			DBGPRINT(RT_DEBUG_ERROR, ("pAd->CSRBaseAddress =0x%lx, csr_addr=0x%lx!\n", (ULONG)pAd->CSRBaseAddress, (ULONG)Data));
			break;

		case CMD_RTPRIV_IOCTL_PCIE_INIT:
			RTMPInitPCIeDevice(pData, pAd);
			break;
#endif /* RTMP_PCI_SUPPORT */

#ifdef RT_CFG80211_SUPPORT
		case CMD_RTPRIV_IOCTL_CFG80211_CFG_START:
			RT_CFG80211_REINIT(pAd);
			RT_CFG80211_CRDA_REG_RULE_APPLY(pAd);
			break;
#endif /* RT_CFG80211_SUPPORT */

#ifdef INF_PPA_SUPPORT
		case CMD_RTPRIV_IOCTL_INF_PPA_INIT:
			os_alloc_mem(NULL, (UCHAR **)&(pAd->pDirectpathCb), sizeof(PPA_DIRECTPATH_CB));
			break;

		case CMD_RTPRIV_IOCTL_INF_PPA_EXIT:
			if (ppa_hook_directpath_register_dev_fn && pAd->PPAEnable==TRUE) 
			{
				UINT status;
				status=ppa_hook_directpath_register_dev_fn(&pAd->g_if_id, pAd->net_dev, NULL, 0);
				DBGPRINT(RT_DEBUG_TRACE, ("unregister PPA:g_if_id=%d status=%d\n",pAd->g_if_id,status));
			}
			os_free_mem(NULL, pAd->pDirectpathCb);
			break;
#endif /* INF_PPA_SUPPORT*/

		case CMD_RTPRIV_IOCTL_VIRTUAL_INF_UP:
		/* interface up */
		{
			RT_CMD_INF_UP_DOWN *pInfConf = (RT_CMD_INF_UP_DOWN *)pData;

			if (VIRTUAL_IF_NUM(pAd) == 0)
			{
				if (pInfConf->rt28xx_open(pAd->net_dev) != 0)
				{
					DBGPRINT(RT_DEBUG_TRACE, ("rt28xx_open return fail!\n"));
					return NDIS_STATUS_FAILURE;
				}
			}
			else
			{
#ifdef CONFIG_AP_SUPPORT
				extern VOID APMakeAllBssBeacon(IN PRTMP_ADAPTER pAd);
				extern VOID  APUpdateAllBeaconFrame(IN PRTMP_ADAPTER pAd);
				APMakeAllBssBeacon(pAd);
				APUpdateAllBeaconFrame(pAd);
#endif /* CONFIG_AP_SUPPORT */
			}
			VIRTUAL_IF_INC(pAd);
		}
			break;

		case CMD_RTPRIV_IOCTL_VIRTUAL_INF_DOWN:
		/* interface down */
		{
			RT_CMD_INF_UP_DOWN *pInfConf = (RT_CMD_INF_UP_DOWN *)pData;

			VIRTUAL_IF_DEC(pAd);
			if (VIRTUAL_IF_NUM(pAd) == 0)
				pInfConf->rt28xx_close(pAd->net_dev);
		}
			break;

		case CMD_RTPRIV_IOCTL_VIRTUAL_INF_GET:
		/* get virtual interface number */
			*(ULONG *)pData = VIRTUAL_IF_NUM(pAd);
			break;

		case CMD_RTPRIV_IOCTL_INF_TYPE_GET:
		/* get current interface type */
			*(ULONG *)pData = pAd->infType;
			break;

		case CMD_RTPRIV_IOCTL_INF_STATS_GET:
			/* get statistics */
			{			
				RT_CMD_STATS *pStats = (RT_CMD_STATS *)pData;
				pStats->pStats = pAd->stats;
				if(pAd->OpMode == OPMODE_STA)
				{
					pStats->rx_packets = pAd->WlanCounters.ReceivedFragmentCount.QuadPart;
					pStats->tx_packets = pAd->WlanCounters.TransmittedFragmentCount.QuadPart;
					pStats->rx_bytes = pAd->RalinkCounters.ReceivedByteCount;
					pStats->tx_bytes = pAd->RalinkCounters.TransmittedByteCount;
					pStats->rx_errors = pAd->Counters8023.RxErrors;
					pStats->tx_errors = pAd->Counters8023.TxErrors;
					pStats->multicast = pAd->WlanCounters.MulticastReceivedFrameCount.QuadPart;   /* multicast packets received*/
					pStats->collisions = pAd->Counters8023.OneCollision + pAd->Counters8023.MoreCollisions;  /* Collision packets*/
					pStats->rx_over_errors = pAd->Counters8023.RxNoBuffer;                   /* receiver ring buff overflow*/
					pStats->rx_crc_errors = 0;/*pAd->WlanCounters.FCSErrorCount;      recved pkt with crc error*/
					pStats->rx_frame_errors = pAd->Counters8023.RcvAlignmentErrors;          /* recv'd frame alignment error*/
					pStats->rx_fifo_errors = pAd->Counters8023.RxNoBuffer;                   /* recv'r fifo overrun*/
				}
#ifdef CONFIG_AP_SUPPORT
				else if(pAd->OpMode == OPMODE_AP)
				{
					INT index;
					for(index = 0; index < MAX_MBSSID_NUM(pAd); index++)
					{
						if (pAd->ApCfg.MBSSID[index].MSSIDDev == (PNET_DEV)(pStats->pNetDev))
						{
							break;
						}
					}
						
					if(index >= MAX_MBSSID_NUM(pAd))
					{
						//reset counters
						pStats->rx_packets = 0;
						pStats->tx_packets = 0;
						pStats->rx_bytes = 0;
						pStats->tx_bytes = 0;
						pStats->rx_errors = 0;
						pStats->tx_errors = 0;
						pStats->multicast = 0;   /* multicast packets received*/
						pStats->collisions = 0;  /* Collision packets*/
						pStats->rx_over_errors = 0; /* receiver ring buff overflow*/
						pStats->rx_crc_errors = 0; /* recved pkt with crc error*/
						pStats->rx_frame_errors = 0; /* recv'd frame alignment error*/
						pStats->rx_fifo_errors = 0; /* recv'r fifo overrun*/
						   
						DBGPRINT(RT_DEBUG_ERROR, ("CMD_RTPRIV_IOCTL_INF_STATS_GET: can not find mbss I/F\n"));
						return NDIS_STATUS_FAILURE;
					}
					
					pStats->rx_packets = pAd->ApCfg.MBSSID[index].RxCount;
					pStats->tx_packets = pAd->ApCfg.MBSSID[index].TxCount;
					pStats->rx_bytes = pAd->ApCfg.MBSSID[index].ReceivedByteCount;
					pStats->tx_bytes = pAd->ApCfg.MBSSID[index].TransmittedByteCount;
					pStats->rx_errors = pAd->ApCfg.MBSSID[index].RxErrorCount;
					pStats->tx_errors = pAd->ApCfg.MBSSID[index].TxErrorCount;
					pStats->multicast = pAd->ApCfg.MBSSID[index].mcPktsRx; /* multicast packets received */
					pStats->collisions = 0;  /* Collision packets*/
					pStats->rx_over_errors = 0;                   /* receiver ring buff overflow*/
					pStats->rx_crc_errors = 0;/* recved pkt with crc error*/
					pStats->rx_frame_errors = 0;          /* recv'd frame alignment error*/
					pStats->rx_fifo_errors = 0;                   /* recv'r fifo overrun*/
				}
#endif
			}
			break;

		case CMD_RTPRIV_IOCTL_INF_IW_STATUS_GET:
		/* get wireless statistics */
		{
			UCHAR CurOpMode = OPMODE_AP;
#ifdef CONFIG_AP_SUPPORT 
			PMAC_TABLE_ENTRY pMacEntry = NULL;
#endif /* CONFIG_AP_SUPPORT */
			RT_CMD_IW_STATS *pStats = (RT_CMD_IW_STATS *)pData;

			pStats->qual = 0;
			pStats->level = 0;
			pStats->noise = 0;
			pStats->pStats = pAd->iw_stats;
			
#ifdef CONFIG_STA_SUPPORT
			if (pAd->OpMode == OPMODE_STA)
			{
				CurOpMode = OPMODE_STA;
#ifdef P2P_SUPPORT
				if (pStats->priv_flags == INT_P2P)
					CurOpMode = OPMODE_AP;
#endif /* P2P_SUPPORT */					
			}
#endif /* CONFIG_STA_SUPPORT */

			/*check if the interface is down*/
			if(!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_INTERRUPT_IN_USE))
			{
				return NDIS_STATUS_FAILURE;
			}

#ifdef CONFIG_AP_SUPPORT
			if (CurOpMode == OPMODE_AP)
			{
#ifdef APCLI_SUPPORT
				if ((pStats->priv_flags == INT_APCLI)
#ifdef P2P_SUPPORT
					|| (P2P_CLI_ON(pAd))
#endif /* P2P_SUPPORT */
					)
				{
					INT ApCliIdx = ApCliIfLookUp(pAd, (PUCHAR)pStats->dev_addr);
					if ((ApCliIdx >= 0) && VALID_WCID(pAd->ApCfg.ApCliTab[ApCliIdx].MacTabWCID))
						pMacEntry = &pAd->MacTab.Content[pAd->ApCfg.ApCliTab[ApCliIdx].MacTabWCID];
				}
				else
#endif /* APCLI_SUPPORT */
				{
					/*
						only AP client support wireless stats function.
						return NULL pointer for all other cases.
					*/
					pMacEntry = NULL;
				}
			}
#endif /* CONFIG_AP_SUPPORT */

#ifdef CONFIG_STA_SUPPORT
			if (CurOpMode == OPMODE_STA)
				pStats->qual = ((pAd->Mlme.ChannelQuality * 12)/10 + 10);
#endif /* CONFIG_STA_SUPPORT */
#ifdef CONFIG_AP_SUPPORT
			if (CurOpMode == OPMODE_AP)
			{
				if (pMacEntry != NULL)
					pStats->qual = ((pMacEntry->ChannelQuality * 12)/10 + 10);
				else
					pStats->qual = ((pAd->Mlme.ChannelQuality * 12)/10 + 10);
			}
#endif /* CONFIG_AP_SUPPORT */

			if (pStats->qual > 100)
				pStats->qual = 100;

#ifdef CONFIG_STA_SUPPORT
			if (CurOpMode == OPMODE_STA)
			{
				pStats->level =
					RTMPMaxRssi(pAd, pAd->StaCfg.RssiSample.AvgRssi0,
									pAd->StaCfg.RssiSample.AvgRssi1,
									pAd->StaCfg.RssiSample.AvgRssi2);
			}
#endif /* CONFIG_STA_SUPPORT */
#ifdef CONFIG_AP_SUPPORT
			if (CurOpMode == OPMODE_AP)
			{
				if (pMacEntry != NULL)
					pStats->level =
						RTMPMaxRssi(pAd, pMacEntry->RssiSample.AvgRssi0,
										pMacEntry->RssiSample.AvgRssi1,
										pMacEntry->RssiSample.AvgRssi2);
#ifdef P2P_APCLI_SUPPORT
				else
					pStats->level =
						RTMPMaxRssi(pAd, pAd->StaCfg.RssiSample.AvgRssi0,
										pAd->StaCfg.RssiSample.AvgRssi1,
										pAd->StaCfg.RssiSample.AvgRssi2);
#endif /* P2P_APCLI_SUPPORT */
			}
#endif /* CONFIG_AP_SUPPORT */

#ifdef CONFIG_AP_SUPPORT
			pStats->noise = RTMPMaxRssi(pAd, pAd->ApCfg.RssiSample.AvgRssi0,
										pAd->ApCfg.RssiSample.AvgRssi1,
										pAd->ApCfg.RssiSample.AvgRssi2) -
										RTMPMinSnr(pAd, pAd->ApCfg.RssiSample.AvgSnr0,
										pAd->ApCfg.RssiSample.AvgSnr1);
#endif /* CONFIG_AP_SUPPORT */
#ifdef CONFIG_STA_SUPPORT
			pStats->noise = RTMPMaxRssi(pAd, pAd->StaCfg.RssiSample.AvgRssi0,
										pAd->StaCfg.RssiSample.AvgRssi1,
										pAd->StaCfg.RssiSample.AvgRssi2) - 
										RTMPMinSnr(pAd, pAd->StaCfg.RssiSample.AvgSnr0, 
										pAd->StaCfg.RssiSample.AvgSnr1);
#endif /* CONFIG_STA_SUPPORT */
		}
			break;

		case CMD_RTPRIV_IOCTL_INF_MAIN_CREATE:
			*(VOID **)pData = RtmpPhyNetDevMainCreate(pAd);
			break;

		case CMD_RTPRIV_IOCTL_INF_MAIN_ID_GET:
			*(ULONG *)pData = INT_MAIN;
			break;

		case CMD_RTPRIV_IOCTL_INF_MAIN_CHECK:
			if (Data != INT_MAIN)
				return NDIS_STATUS_FAILURE;
			break;

		case CMD_RTPRIV_IOCTL_INF_P2P_CHECK:
			if (Data != INT_P2P)
				return NDIS_STATUS_FAILURE;
			break;

#ifdef WDS_SUPPORT
		case CMD_RTPRIV_IOCTL_WDS_INIT:
			WDS_Init(pAd, pData);
			break;

		case CMD_RTPRIV_IOCTL_WDS_REMOVE:
			WDS_Remove(pAd);
			break;

		case CMD_RTPRIV_IOCTL_WDS_STATS_GET:
			if (Data == INT_WDS)
			{
				if (WDS_StatsGet(pAd, pData) != TRUE)
					return NDIS_STATUS_FAILURE;
			}
			else
				return NDIS_STATUS_FAILURE;
			break;
#endif /* WDS_SUPPORT */

#ifdef RALINK_ATE
#ifdef RALINK_QA
		case CMD_RTPRIV_IOCTL_ATE:
			RtmpDoAte(pAd, wrq, pData);
			break;
#endif /* RALINK_QA */ 
#endif /* RALINK_ATE */

		case CMD_RTPRIV_IOCTL_MAC_ADDR_GET:

			RT28xx_EEPROM_READ16(pAd, 0x04, Addr01);
			RT28xx_EEPROM_READ16(pAd, 0x06, Addr23);
			RT28xx_EEPROM_READ16(pAd, 0x08, Addr45);			
			
			PermanentAddress[0] = (UCHAR)(Addr01 & 0xff);		
			PermanentAddress[1] = (UCHAR)(Addr01 >> 8);
			PermanentAddress[2] = (UCHAR)(Addr23 & 0xff);
			PermanentAddress[3] = (UCHAR)(Addr23 >> 8);
			PermanentAddress[4] = (UCHAR)(Addr45 & 0xff);
			PermanentAddress[5] = (UCHAR)(Addr45 >> 8);				
			
			for(i=0; i<6; i++)
				*(UCHAR *)(pData+i) = PermanentAddress[i];
			break;
#ifdef CONFIG_AP_SUPPORT
		case CMD_RTPRIV_IOCTL_AP_SIOCGIWRATEQ:
		/* handle for SIOCGIWRATEQ */
		{
			RT_CMD_IOCTL_RATE *pRate = (RT_CMD_IOCTL_RATE *)pData;
			HTTRANSMIT_SETTING HtPhyMode;

#ifdef APCLI_SUPPORT
			if (pRate->priv_flags == INT_APCLI)
				HtPhyMode = pAd->ApCfg.ApCliTab[pObj->ioctl_if].HTPhyMode;
			else
#endif /* APCLI_SUPPORT */
#ifdef WDS_SUPPORT
			if (pRate->priv_flags == INT_WDS)
				HtPhyMode = pAd->WdsTab.WdsEntry[pObj->ioctl_if].HTPhyMode;
			else
#endif /* WDS_SUPPORT */
			{
				HtPhyMode = pAd->ApCfg.MBSSID[pObj->ioctl_if].HTPhyMode;
#ifdef MBSS_SUPPORT
				/* reset phy mode for MBSS */
				MBSS_PHY_MODE_RESET(pObj->ioctl_if, HtPhyMode);
#endif /* MBSS_SUPPORT */
			}
			RtmpDrvMaxRateGet(pAd, HtPhyMode.field.MODE, HtPhyMode.field.ShortGI,
							HtPhyMode.field.BW, HtPhyMode.field.MCS,
							(UINT32 *)&pRate->BitRate);
		}
			break;
#endif /* CONFIG_AP_SUPPORT */

		case CMD_RTPRIV_IOCTL_SIOCGIWNAME:
			RtmpIoctl_rt_ioctl_giwname(pAd, pData, 0);
			break;

	}

#ifdef RT_CFG80211_SUPPORT
	if ((CMD_RTPRIV_IOCTL_80211_START <= cmd) &&
		(cmd <= CMD_RTPRIV_IOCTL_80211_END))
	{
		CFG80211DRV_IoctlHandle(pAd, wrq, cmd, subcmd, pData, Data);
	}
#endif /* RT_CFG80211_SUPPORT */

	if (cmd >= CMD_RTPRIV_IOCTL_80211_COM_LATEST_ONE)
		return NDIS_STATUS_FAILURE;

	return Status;
}

/* 
    ==========================================================================
    Description:
        Issue a site survey command to driver
	Arguments:
	    pAdapter                    Pointer to our adapter
	    wrq                         Pointer to the ioctl argument

    Return Value:
        None

    Note:
        Usage: 
               1.) iwpriv ra0 set site_survey
    ==========================================================================
*/
INT Set_SiteSurvey_Proc(
	IN	PRTMP_ADAPTER	pAd, 
	IN	PSTRING			arg)
{
	NDIS_802_11_SSID Ssid;
	POS_COOKIE pObj;

	pObj = (POS_COOKIE) pAd->OS_Cookie;

	//check if the interface is down
	if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_INTERRUPT_IN_USE))
	{
		DBGPRINT(RT_DEBUG_TRACE, ("INFO::Network is down!\n"));
		return -ENETDOWN;   
	}

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		if (MONITOR_ON(pAd))
    	{
        	DBGPRINT(RT_DEBUG_TRACE, ("!!! Driver is in Monitor Mode now !!!\n"));
        	return -EINVAL;
    	}
	}
#endif // CONFIG_STA_SUPPORT //

    NdisZeroMemory(&Ssid, sizeof(NDIS_802_11_SSID));

#ifdef CONFIG_AP_SUPPORT
#ifdef AP_SCAN_SUPPORT
#ifdef P2P_SUPPORT
	if (pObj->ioctl_if_type == INT_P2P)
#else
	IF_DEV_CONFIG_OPMODE_ON_AP(pAd)
#endif /* P2P_SUPPORT */
	{
		if ((strlen(arg) != 0) && (strlen(arg) <= MAX_LEN_OF_SSID))
    	{
        	NdisMoveMemory(Ssid.Ssid, arg, strlen(arg));
        	Ssid.SsidLength = strlen(arg);
		}

		if (Ssid.SsidLength == 0)
			ApSiteSurvey(pAd, &Ssid, SCAN_PASSIVE, FALSE);
		else
			ApSiteSurvey(pAd, &Ssid, SCAN_ACTIVE, FALSE);

		return TRUE;
	}
#endif /* AP_SCAN_SUPPORT */
#endif // CONFIG_AP_SUPPORT //

#ifdef CONFIG_STA_SUPPORT
	IF_DEV_CONFIG_OPMODE_ON_STA(pAd)
	{
		Ssid.SsidLength = 0; 
		if ((arg != NULL) &&
			(strlen(arg) <= MAX_LEN_OF_SSID))
		{
			RTMPMoveMemory(Ssid.Ssid, arg, strlen(arg));
			Ssid.SsidLength = strlen(arg);
		}

		pAd->StaCfg.bSkipAutoScanConn = TRUE;
		StaSiteSurvey(pAd, &Ssid, SCAN_ACTIVE);
	}
#endif // CONFIG_STA_SUPPORT //

	DBGPRINT(RT_DEBUG_TRACE, ("Set_SiteSurvey_Proc\n"));

    return TRUE;
}

INT	Set_Antenna_Proc(
	IN	PRTMP_ADAPTER	pAd, 
	IN	PSTRING			arg)
{
	ANT_DIVERSITY_TYPE UsedAnt;
	int i;
	DBGPRINT(RT_DEBUG_OFF, ("==> Set_Antenna_Proc *******************\n"));

	for (i = 0; i < strlen(arg); i++)
		if (!isdigit(arg[i]))
			return -EINVAL;

	UsedAnt = simple_strtol(arg, 0, 10);

	switch (UsedAnt)
	{
		/* 2: Fix in the PHY Antenna CON1*/
		case ANT_FIX_ANT0:
			AsicSetRxAnt(pAd, 0);
			DBGPRINT(RT_DEBUG_OFF, ("<== Set_Antenna_Proc(Fix in Ant CON1), (%d,%d)\n", 
					pAd->RxAnt.Pair1PrimaryRxAnt, pAd->RxAnt.Pair1SecondaryRxAnt));
			break;
    	/* 3: Fix in the PHY Antenna CON2*/
		case ANT_FIX_ANT1:
			AsicSetRxAnt(pAd, 1);
			DBGPRINT(RT_DEBUG_OFF, ("<== %s(Fix in Ant CON2), (%d,%d)\n", 
							__FUNCTION__, pAd->RxAnt.Pair1PrimaryRxAnt, pAd->RxAnt.Pair1SecondaryRxAnt));
			break;
		default:
			DBGPRINT(RT_DEBUG_ERROR, ("<== %s(N/A cmd: %d), (%d,%d)\n", __FUNCTION__, UsedAnt,
					pAd->RxAnt.Pair1PrimaryRxAnt, pAd->RxAnt.Pair1SecondaryRxAnt));
			break;
	}
	
	return TRUE;
}
			
#ifdef RT5350
INT Set_Hw_Antenna_Div_Proc(
	IN	PRTMP_ADAPTER	pAd,
	IN	PSTRING			arg)
{
	return Set_Antenna_Proc(pAd, arg);	
}
#endif /* RT5350 */

#ifdef RT6352
INT Set_RfBankSel_Proc(
    IN  PRTMP_ADAPTER pAd, 
    IN  PSTRING	arg)
{
	LONG RfBank;

	RfBank = simple_strtol(arg, 0, 10);

	pAd->RfBank = RfBank;

	return TRUE;
}

#ifdef RTMP_TEMPERATURE_CALIBRATION
INT Set_TemperatureCAL_Proc(
	IN	PRTMP_ADAPTER pAd, 
	IN	PSTRING arg)
{
	RT6352_Temperature_Init(pAd);
	return TRUE;
}
#endif /* RTMP_TEMPERATURE_CALIBRATION */
#endif /* RT6352 */

#ifdef MCS_LUT_SUPPORT
INT Set_HwTxRateLookUp_Proc(
	IN RTMP_ADAPTER	*pAd,
	IN PSTRING arg)
{
	UCHAR Enable;
	UINT32 MacReg;

	Enable = simple_strtol(arg, 0, 10);

	RTMP_IO_READ32(pAd, TX_FBK_LIMIT, &MacReg);
	if (Enable)
	{
		MacReg |= 0x00040000;
		pAd->bUseHwTxLURate = TRUE;
		DBGPRINT(RT_DEBUG_TRACE, ("==>UseHwTxLURate (ON)\n"));
	}
	else
	{
		MacReg &= (~0x00040000);
		pAd->bUseHwTxLURate = FALSE;
		DBGPRINT(RT_DEBUG_TRACE, ("==>UseHwTxLURate (OFF)\n"));
	}
	RTMP_IO_WRITE32(pAd, TX_FBK_LIMIT, MacReg);

	DBGPRINT(RT_DEBUG_WARN, ("UseHwTxLURate = %d \n", pAd->bUseHwTxLURate));

	return TRUE;
}
#endif /* MCS_LUT_SUPPORT */

