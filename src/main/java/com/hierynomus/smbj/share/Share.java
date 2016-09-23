/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.smbj.share;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileInfo;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.smb2.SMB2CreateDisposition;
import com.hierynomus.smbj.smb2.SMB2CreateOptions;
import com.hierynomus.smbj.smb2.SMB2FileId;
import com.hierynomus.smbj.smb2.SMB2ShareAccess;
import com.hierynomus.smbj.smb2.messages.SMB2Close;
import com.hierynomus.smbj.smb2.messages.SMB2CreateRequest;
import com.hierynomus.smbj.smb2.messages.SMB2CreateResponse;
import com.hierynomus.smbj.smb2.messages.SMB2QueryInfoRequest;
import com.hierynomus.smbj.smb2.messages.SMB2QueryInfoResponse;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.EnumSet;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class Share implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(Share.class);

    protected final TreeConnect treeConnect;
    private AtomicBoolean disconnected = new AtomicBoolean(false);

    public Share(SmbPath smbPath, TreeConnect treeConnect) {
        this.treeConnect = treeConnect;
        treeConnect.setHandle(this);
    }

    @Override
    public void close() throws IOException {
        if (!disconnected.get()) {
            treeConnect.close(this);
        }
    }

    void disconnect() {
        disconnected.set(true);
    }

    public boolean isConnected() {
        return !disconnected.get();
    }

    public TreeConnect getTreeConnect() {
        return treeConnect;
    }

    public SMB2FileId open(
            String path, long accessMask,
            EnumSet<FileAttributes> fileAttributes, EnumSet<SMB2ShareAccess> shareAccess,
            SMB2CreateDisposition createDisposition, EnumSet<SMB2CreateOptions> createOptions)
            throws TransportException, SMBApiException {
        logger.info("open {},{}", path);

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();
        SMB2CreateRequest cr = openFileRequest(
                treeConnect, path, accessMask, shareAccess, fileAttributes, createDisposition, createOptions);
        Future<SMB2CreateResponse> responseFuture = connection.send(cr);
        SMB2CreateResponse cresponse = Futures.get(responseFuture, TransportException.Wrapper);

        if (cresponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(cresponse.getHeader().getStatus(),
                    cresponse.getHeader().getStatusCode(),
                    "Create failed for " + path);
        }

        return cresponse.getFileId();
    }


    protected static SMB2CreateRequest openFileRequest(
            TreeConnect treeConnect, String path,
            long accessMask,
            EnumSet<SMB2ShareAccess> shareAccess,
            EnumSet<FileAttributes> fileAttributes,
            SMB2CreateDisposition createDisposition,
            EnumSet<SMB2CreateOptions> createOptions) {

        Session session = treeConnect.getSession();
        SMB2CreateRequest cr = new SMB2CreateRequest(
                session.getConnection().getNegotiatedDialect(),
                session.getSessionId(), treeConnect.getTreeId(),
                accessMask,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions, path);
        return cr;
    }

    public void close(SMB2FileId fileId) throws TransportException, SMBApiException {
        Connection connection = treeConnect.getSession().getConnection();
        SMB2Close closeReq = new SMB2Close(
                connection.getNegotiatedDialect(),
                treeConnect.getSession().getSessionId(), treeConnect.getTreeId(), fileId);
        Future<SMB2Close> closeFuture = connection.send(closeReq);
        SMB2Close closeResp = Futures.get(closeFuture, TransportException.Wrapper);

        if (closeResp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(closeResp.getHeader().getStatus(),
                    closeResp.getHeader().getStatusCode(),
                    "Close failed for " + fileId);
        }
    }
}
