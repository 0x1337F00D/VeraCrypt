#include "EMVCard.h"
#include "TLVParser.h"
#include "SCardReader.h"
#include "PCSCException.h"

#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include <vector>
#include <iostream>
#include <algorithm>

#if !defined(TC_WINDOWS) || defined(TC_PROTOTYPE)
#include "Platform/SerializerFactory.h"
#include "Platform/StringConverter.h"
#include "Platform/SystemException.h"
#else
#include "Dictionary.h"
#include "Language.h"
#endif

using namespace std;

namespace VeraCrypt
{
#ifndef TC_WINDOWS
	wstring ArrayToHexWideString(const unsigned char * pbData, size_t cbData)
	{
		static const wchar_t* hexChar = L"0123456789ABCDEF";
		wstring result;
		if (pbData)
		{
			for (size_t i = 0; i < cbData; i++)
			{
				result += hexChar[pbData[i] >> 4];
				result += hexChar[pbData[i] & 0x0F];
			}
		}

		return result;
	}
#endif

	map<EMVCardType, vector<uint8>> InitializeSupportedAIDs()
	{
		map<EMVCardType, vector<uint8>> supportedAIDs;
		supportedAIDs.insert(std::make_pair(EMVCardType::AMEX, vector<uint8>(EMVCard::AMEX_AID, EMVCard::AMEX_AID + sizeof(EMVCard::AMEX_AID))));
		supportedAIDs.insert(std::make_pair(EMVCardType::MASTERCARD, vector<uint8>(EMVCard::MASTERCARD_AID, EMVCard::MASTERCARD_AID + sizeof(EMVCard::MASTERCARD_AID))));
		supportedAIDs.insert(std::make_pair(EMVCardType::VISA, vector<uint8>(EMVCard::VISA_AID, EMVCard::VISA_AID + sizeof(EMVCard::VISA_AID))));
		return supportedAIDs;
	}

	const uint8 EMVCard::AMEX_AID[7]										= {0xA0, 0x00, 0x00, 0x00, 0x00, 0x25, 0x10};
	const uint8 EMVCard::MASTERCARD_AID[7]								= {0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10};
	const uint8 EMVCard::VISA_AID[7]										= {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};
	const map<EMVCardType, vector<uint8>> EMVCard::SUPPORTED_AIDS		= InitializeSupportedAIDs();

	const uint16 EMV_PDOL_TAG = 0x9F38;
	const uint8 INS_GET_PROCESSING_OPTIONS = 0xA8;
	const uint8 EMV_GPO_RESPONSE_FORMAT1_TAG = 0x80;
	const uint8 EMV_GPO_RESPONSE_FORMAT2_TAG = 0x77;
	const uint8 EMV_AIP_TAG = 0x82;
	const uint8 EMV_AFL_TAG = 0x94;

	EMVCard::EMVCard() : SCard(), m_lastPANDigits(L"")
	{
	}
	
	EMVCard::EMVCard(size_t slotId) : SCard(slotId), m_lastPANDigits(L"")
    {
    }

    EMVCard::~EMVCard()
    {
		Clear();
    }

	EMVCard::EMVCard(const EMVCard& other) :
			SCard(other),
			m_aid(other.m_aid),
			m_supportedAids(other.m_supportedAids),
			m_iccCert(other.m_iccCert),
			m_issuerCert(other.m_issuerCert),
			m_cplcData(other.m_cplcData),
			m_lastPANDigits(other.m_lastPANDigits)
	{
	}

	EMVCard::EMVCard(EMVCard&& other) :
			SCard(other),
			m_aid(std::move(other.m_aid)),
			m_supportedAids(std::move(other.m_supportedAids)),
			m_iccCert(std::move(other.m_iccCert)),
			m_issuerCert(std::move(other.m_issuerCert)),
			m_cplcData(std::move(other.m_cplcData)),
			m_lastPANDigits(std::move(other.m_lastPANDigits))
	{
	}
	
	EMVCard& EMVCard::operator = (const EMVCard& other)
	{
		if (this != &other)
		{
			SCard::operator=(other);
			m_aid = other.m_aid;
			m_supportedAids = other.m_supportedAids;
			m_iccCert = other.m_iccCert;
			m_issuerCert = other.m_issuerCert;
			m_cplcData = other.m_cplcData;
			m_lastPANDigits = other.m_lastPANDigits;
		}
		return *this;
	}
	
	EMVCard& EMVCard::operator = (EMVCard&& other)
	{
		if (this != &other)
		{
			SCard::operator=(other);
			m_reader = std::move(other.m_reader);
			m_aid = std::move(other.m_aid);
			m_supportedAids = std::move(other.m_supportedAids);
			m_iccCert = std::move(other.m_iccCert);
			m_issuerCert = std::move(other.m_issuerCert);
			m_cplcData = std::move(other.m_cplcData);
			m_lastPANDigits = std::move(other.m_lastPANDigits);
		}
		return *this;
	}

	void EMVCard::Clear(void)
	{
		m_aid.clear();
		m_supportedAids.clear();
		m_iccCert.clear();
		m_issuerCert.clear();
		m_cplcData.clear();
		m_lastPANDigits.clear();
	}

	vector<EMVCard::EmvAflEntry> EMVCard::ProcessGPO(shared_ptr<TLVNode> fciNode)
	{
		vector<EmvAflEntry> aflEntries;
		CommandAPDU command;
		ResponseAPDU response;
		vector<uint8> pdolData;
		vector<uint8> gpoData;
		shared_ptr<TLVNode> pdolNode = TLVParser::TLV_Find(fciNode, EMV_PDOL_TAG);
		size_t pdolLen = 0;

		if (pdolNode && pdolNode->Value->size() > 0)
		{
			size_t index = 0;
			vector<uint8>& val = *pdolNode->Value;
			while (index < val.size())
			{
				uint8 tag = val[index++];
				if ((tag & 0x1F) == 0x1F && index < val.size())
					index++; // skip second byte of tag

				if (index < val.size())
				{
					uint8 len = val[index++];
					pdolLen += len;
				}
			}
		}

		gpoData.push_back(0x83);
		gpoData.push_back((uint8)pdolLen);
		if (pdolLen > 0)
		{
			gpoData.insert(gpoData.end(), pdolLen, 0);
		}

		command = CommandAPDU(0x80, INS_GET_PROCESSING_OPTIONS, 0x00, 0x00, gpoData, SCardReader::shortAPDUMaxTransSize);
		m_reader->ApduProcessData(command, response);

		if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
		{
			vector<uint8> rData = response.getData();
			shared_ptr<TLVNode> gpoRoot = TLVParser::TLV_Parse(rData.data(), rData.size());

			if (gpoRoot)
			{
				vector<uint8> aflData;
				if (gpoRoot->Tag == EMV_GPO_RESPONSE_FORMAT1_TAG)
				{
					if (gpoRoot->Value->size() >= 2)
					{
						// Skip first 2 bytes (AIP)
						aflData.assign(gpoRoot->Value->begin() + 2, gpoRoot->Value->end());
					}
				}
				else if (gpoRoot->Tag == EMV_GPO_RESPONSE_FORMAT2_TAG)
				{
					shared_ptr<TLVNode> aflNode = TLVParser::TLV_Find(gpoRoot, EMV_AFL_TAG);
					if (aflNode)
						aflData = *aflNode->Value;
				}

				size_t idx = 0;
				while (idx + 3 < aflData.size())
				{
					EmvAflEntry entry;
					entry.sfi = aflData[idx] >> 3;
					entry.startRec = aflData[idx+1];
					entry.endRec = aflData[idx+2];
					aflEntries.push_back(entry);
					idx += 4;
				}
			}
		}

		return aflEntries;
	}

	vector<pair<uint8, uint8>> EMVCard::GetRecordsToRead(const vector<EmvAflEntry>& aflEntries)
	{
		vector<pair<uint8, uint8>> recordsToRead;
		if (aflEntries.size() > 0)
		{
			for (const auto& entry : aflEntries)
			{
				for (uint8 rec = entry.startRec; rec <= entry.endRec; rec++)
					recordsToRead.push_back(make_pair(entry.sfi, rec));
			}
		}
		else
		{
			for (uint8 sfi = 1; sfi < 32; sfi++)
			{
				for (uint8 rec = 1; rec < 17; rec++)
					recordsToRead.push_back(make_pair(sfi, rec));
			}
		}
		return recordsToRead;
	}

	vector<uint8> EMVCard::GetCardAID(bool forceContactless)
	{
		vector<vector<uint8>> 				supportedAIDs;
		vector<uint8> 						supportedAIDsPriorities;
		vector<pair<uint8, vector<uint8>>> 	supportedAIDsSorted;
		bool 								hasBeenReset = false;
		CommandAPDU 						command;
		ResponseAPDU 						response;
		vector<uint8> 						responseData;
		shared_ptr<TLVNode> 				rootNode;
		shared_ptr<TLVNode> 				fciNode;
		shared_ptr<TLVNode> 				dfNameNode;
		shared_ptr<TLVNode> 				sfiNode;
		shared_ptr<TLVNode> 				fciIssuerNode;
		shared_ptr<TLVNode> 				fciIssuerDiscretionaryDataNode;
		shared_ptr<TLVNode> 				templateNode;
		vector<shared_ptr<TLVNode>> 		pseDirectoryNodes;
		unsigned char 						sfi;
		bool 								usingContactless = false;
		vector<uint8>						tokenAID;

		if (m_aid.size())
			return m_aid;

		if (m_reader)
		{
			if (m_reader->IsCardPresent())
			{
				m_reader->Connect(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, hasBeenReset, true);
				m_reader->BeginTransaction();
				finally_do_arg (shared_ptr<SCardReader>, m_reader, { finally_arg->EndTransaction(); });

				try
				{
					for (auto it = EMVCard::SUPPORTED_AIDS.begin(); it != EMVCard::SUPPORTED_AIDS.end(); it++)
					{
						command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, it->second, SCardReader::shortAPDUMaxTransSize);
						m_reader->ApduProcessData(command, response);
						if (response.getSW() == SW_NO_ERROR)
						{
							tokenAID = it->second;
							break;
						}
					}

					if (tokenAID.size())
					{
						m_supportedAids.push_back(tokenAID);
						m_aid = tokenAID;
					}
					else
					{
						// The following code retrieves the supported AIDs from the card using PSE.
						// If the card supports more than one AID, the returned list is sorted using the AIDs priorities,
						// the first AID being the one with more priority.
						if (forceContactless)
						{
							usingContactless = true;
							command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, EMV_PSE2, 0, sizeof(EMV_PSE2), SCardReader::shortAPDUMaxTransSize);
							m_reader->ApduProcessData(command, response);
						}
						else 
						{
							command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, EMV_PSE1, 0, sizeof(EMV_PSE1), SCardReader::shortAPDUMaxTransSize);
							m_reader->ApduProcessData(command, response);
							if (response.getSW() != SW_NO_ERROR)
							{
								// EMV_PSE2 not found, try EMV_PSE1
								usingContactless = true;
								command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, EMV_PSE2, 0, sizeof(EMV_PSE2), SCardReader::shortAPDUMaxTransSize);
								m_reader->ApduProcessData(command, response);
							}
						}
						if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
						{
							responseData = response.getData();
							rootNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
							fciNode = TLVParser::TLV_Find(rootNode, EMV_FCI_TAG);
							if (fciNode && fciNode->Subs->size() >= 2)
							{
								if (usingContactless)
								{
									fciIssuerNode = TLVParser::TLV_Find(fciNode, EMV_FCI_ISSUER_TAG);
									if (fciIssuerNode && fciIssuerNode->Subs->size() >= 1)
									{
										fciIssuerDiscretionaryDataNode = TLVParser::TLV_Find(fciIssuerNode, EMV_FCI_ISSUER_DISCRETIONARY_DATA_TAG);
										if (fciIssuerDiscretionaryDataNode && fciIssuerDiscretionaryDataNode->Subs->size() >= 1)
										{
											for (size_t i = 0; i < fciIssuerDiscretionaryDataNode->Subs->size(); i++)
											{
												if (fciIssuerDiscretionaryDataNode->Subs->at(i)->Tag == EMV_DIRECTORY_ENTRY_TAG)
												{
													pseDirectoryNodes.push_back(fciIssuerDiscretionaryDataNode->Subs->at(i));
												}
											}
										}
									}
								}
								else
								{
									dfNameNode = TLVParser::TLV_Find(fciNode, EMV_DFNAME_TAG);
									if (dfNameNode)
									{
										fciIssuerNode = TLVParser::TLV_Find(fciNode, EMV_FCI_ISSUER_TAG);
										if (fciIssuerNode)
										{
											sfiNode = TLVParser::TLV_Find(fciIssuerNode, EMV_SFI_TAG);
											if (sfiNode && sfiNode->Value->size() == 1)
											{
												sfi = sfiNode->Value->at(0);

												uint8 rec = 1;
												do
												{
													command = CommandAPDU(CLA_ISO7816, INS_READ_RECORD, rec++, (sfi << 3) | 4, SCardReader::shortAPDUMaxTransSize);
													m_reader->ApduProcessData(command, response);
													if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
													{
														responseData = response.getData();

														try
														{
															templateNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
															if (templateNode && templateNode->Tag == EMV_TEMPLATE_TAG && templateNode->Subs->size() >= 1)
															{
																for (size_t i = 0; i < templateNode->Subs->size(); i++)
																{
																	if (templateNode->Subs->at(i)->Tag == EMV_DIRECTORY_ENTRY_TAG)
																	{
																		pseDirectoryNodes.push_back(templateNode->Subs->at(i));
																	}
																}
															}
														}
														catch(TLVException)
														{
															continue;
														}
													}
												} while (response.getData().size() > 0);
											}
										}
									}
								}
							}
						}

						for (size_t i = 0; i < pseDirectoryNodes.size(); i++)
						{
							shared_ptr<TLVNode> aidNode;
							shared_ptr<TLVNode> aidPriorityNode;
							aidNode = TLVParser::TLV_Find(pseDirectoryNodes[i], EMV_AID_TAG);
							aidPriorityNode = TLVParser::TLV_Find(pseDirectoryNodes[i], EMV_PRIORITY_TAG);
							if (aidNode && aidNode->Value->size() > 0 && aidPriorityNode && aidPriorityNode->Value->size() == 1)
							{
								supportedAIDs.push_back(*aidNode->Value.get());
								supportedAIDsPriorities.push_back(aidNode->Value->at(0));
							}
						}
						for(size_t i = 0; i < supportedAIDs.size(); i++)
						{
							supportedAIDsSorted.push_back(make_pair(supportedAIDsPriorities[i], supportedAIDs[i]));
						}
						std::sort(supportedAIDsSorted.begin(), supportedAIDsSorted.end());
						for(size_t i = 0; i < supportedAIDs.size(); i++)
						{
							supportedAIDs[i] = supportedAIDsSorted[i].second;
						}

						if (supportedAIDs.size())
						{
							m_supportedAids = supportedAIDs;
							tokenAID = supportedAIDs[0];
							m_aid = tokenAID;
						}
					}
				}
				catch (...)
				{
				}
			}
		}

		return tokenAID;
	}

	void EMVCard::GetCardContent(vector<uint8>& iccCert, vector<uint8>& issuerCert, vector<uint8>& cplcData)
	{
		bool						hasBeenReset	= false;
		bool						aidSelected		= false;
		bool						iccFound		= false;
		bool						issuerFound		= false;
		bool						cplcFound		= false;
		vector<uint8>				emvCardAid;
		shared_ptr<TLVNode>			rootNode;
		shared_ptr<TLVNode>			iccPublicKeyCertNode;
		shared_ptr<TLVNode>			issuerPublicKeyCertNode;
		CommandAPDU					command;
		ResponseAPDU				response;
		vector<uint8>				responseData;

		iccCert.clear();
		issuerCert.clear();
		cplcData.clear();

		if (m_iccCert.size() && m_issuerCert.size() && m_cplcData.size())
		{
			iccCert = m_iccCert;
			issuerCert = m_issuerCert;
			cplcData = m_cplcData;
			return;
		}

		emvCardAid = GetCardAID();
		if (emvCardAid.size() == 0)
		{
			throw EMVUnknownCardType();
		}

		if (m_reader)
		{
			if (m_reader->IsCardPresent())
			{
				m_reader->Connect(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, hasBeenReset, true);
				m_reader->BeginTransaction();
				finally_do_arg (shared_ptr<SCardReader>, m_reader, { finally_arg->EndTransaction(); });

				// First get CPLC before selecting the AID of the card.
				command = CommandAPDU(0x80, INS_GET_DATA, (EMV_CPLC_TAG >> 8) & 0xFF, EMV_CPLC_TAG & 0xFF, SCardReader::shortAPDUMaxTransSize);
				m_reader->ApduProcessData(command, response);
				if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
				{
					cplcFound = true;
					cplcData = response.getData();

					// Then get the certs.
					command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, emvCardAid, SCardReader::shortAPDUMaxTransSize);
					m_reader->ApduProcessData(command, response);
					if (response.getSW() == SW_NO_ERROR)
					{
						aidSelected = true;

						vector<pair<uint8, uint8>> recordsToRead;
						vector<EmvAflEntry> aflEntries;

						try
						{
							responseData = response.getData();
							shared_ptr<TLVNode> fciNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
							aflEntries = ProcessGPO(fciNode);
						}
						catch (...) { }

						recordsToRead = GetRecordsToRead(aflEntries);

						for (const auto& recordInfo : recordsToRead)
						{
							if (iccFound && issuerFound)
								break;

							uint8 sfi = recordInfo.first;
							uint8 rec = recordInfo.second;

							command = CommandAPDU(CLA_ISO7816, INS_READ_RECORD, rec, (sfi << 3) | 4, SCardReader::shortAPDUMaxTransSize);
							m_reader->ApduProcessData(command, response);
							if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
							{
								responseData = response.getData();

								try
								{
									rootNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
								}
								catch(TLVException)
								{
									continue;
								}

								iccPublicKeyCertNode = TLVParser::TLV_Find(rootNode, EMV_ICC_PK_CERT_TAG);
								if (iccPublicKeyCertNode && iccPublicKeyCertNode->Value->size() > 0)
								{
									iccFound = true;
									iccCert = *iccPublicKeyCertNode->Value.get();
								}

								issuerPublicKeyCertNode = TLVParser::TLV_Find(rootNode, EMV_ISS_PK_CERT_TAG);
								if (issuerPublicKeyCertNode && issuerPublicKeyCertNode->Value->size() > 0)
								{
									issuerFound = true;
									issuerCert = *issuerPublicKeyCertNode->Value.get();
								}
							}
						}
					}
				}
			}
		}

		if (!cplcFound)
			throw EMVCPLCNotFound();

		if (!aidSelected)
			throw EMVSelectAIDFailed();

		if (!iccFound)
			throw EMVIccCertNotFound();

		if (!issuerFound)
			throw EMVIssuerCertNotFound();

		m_iccCert = iccCert;
		m_issuerCert = issuerCert;
		m_cplcData = cplcData;
	}

	void EMVCard::GetCardPAN(wstring& lastPANDigits)
	{
		bool						hasBeenReset	= false;
		bool						panFound		= false;
		bool						aidSelected		= false;
		vector<uint8>				EMVCardAid;
		vector<uint8>				panData;
		shared_ptr<TLVNode>			rootNode;
		shared_ptr<TLVNode>			panNode;
		CommandAPDU					command;
		ResponseAPDU				response;
		vector<uint8>				responseData;

		lastPANDigits = L"";

		if (m_lastPANDigits != L"")
		{
			lastPANDigits = m_lastPANDigits;
			return;
		}

		EMVCardAid = GetCardAID();
		if (EMVCardAid.size() == 0)
		{
			throw EMVUnknownCardType();
		}

		if (m_reader)
		{
			if (m_reader->IsCardPresent())
			{
				m_reader->Connect(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, hasBeenReset, true);
				m_reader->BeginTransaction();
				finally_do_arg (shared_ptr<SCardReader>, m_reader, { finally_arg->EndTransaction(); });

				command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, EMVCardAid, SCardReader::shortAPDUMaxTransSize);
				m_reader->ApduProcessData(command, response);
				if (response.getSW() == SW_NO_ERROR)
				{
					aidSelected = true;

					vector<pair<uint8, uint8>> recordsToRead;
					vector<EmvAflEntry> aflEntries;

					try
					{
						responseData = response.getData();
						shared_ptr<TLVNode> fciNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
						aflEntries = ProcessGPO(fciNode);
					}
					catch (...) { }

					recordsToRead = GetRecordsToRead(aflEntries);

					for (const auto& recordInfo : recordsToRead)
					{
						if (panFound)
							break;

						uint8 sfi = recordInfo.first;
						uint8 rec = recordInfo.second;

						command = CommandAPDU(CLA_ISO7816, INS_READ_RECORD, rec, (sfi << 3) | 4, SCardReader::shortAPDUMaxTransSize);
						m_reader->ApduProcessData(command, response);
						if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
						{
							responseData = response.getData();

							try
							{
								rootNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
							}
							catch(TLVException)
							{
								continue;
							}

							panNode = TLVParser::TLV_Find(rootNode, EMV_PAN_TAG);
							if (panNode && panNode->Value->size() >= 8)
							{
								panFound = true;
								panData = *panNode->Value.get();
								panData = vector<uint8>(panData.rbegin(), panData.rbegin() + 2); // only interested in last digits
								std::swap(panData[0], panData[1]);
								lastPANDigits = ArrayToHexWideString(panData.data(), (int) panData.size());
							}
						}
					}
				}
			}
		}
		
		if (panData.size())
			burn(panData.data(), panData.size());

		if (!aidSelected)
			throw EMVSelectAIDFailed();

		if (!panFound)
			throw EMVPANNotFound();

		m_lastPANDigits = lastPANDigits;
	}
}
