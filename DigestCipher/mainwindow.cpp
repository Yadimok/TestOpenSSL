/*
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    setWindowTitle(tr("DigestCipher"));

    mMainBoxLayout = new QHBoxLayout();
    mTabWidget  = new QTabWidget();
    mMainBoxLayout->addWidget(mTabWidget);
    ui->centralwidget->setLayout(mMainBoxLayout);

    mWidgetDigest = new QWidget();
    mWidgetCipher = new QWidget();

    mTabWidget->addTab(mWidgetDigest, tr("Message digest"));
    QVBoxLayout *vBoxLayoutMD = new QVBoxLayout();
    mGroupBoxDigest = new QGroupBox();
    mLabelHashResult = new QLabel;
    mLabelHashResult->setText(tr("Hash:"));
    mLabelFileName = new QLabel;
    mLineEditResult = new QLineEdit;
    mLineEditResult->setReadOnly(true);
    mLineEditResult->setFont(QFont("Arial", 12));
    mRadioButtonMD4 = new QRadioButton;
    mRadioButtonMD4->setText(tr("MD4"));
    mRadioButtonMD5 = new QRadioButton;
    mRadioButtonMD5->setText(tr("MD5"));
    mRadioButtonRMD160 = new QRadioButton;
    mRadioButtonRMD160->setText(tr("RIPEMD160"));
    mRadiobuttonSha1 = new QRadioButton;
    mRadiobuttonSha1->setText(tr("SHA1"));
    mRadiobuttonSha224 = new QRadioButton;
    mRadiobuttonSha224->setText(tr("SHA224"));
    mRadiobuttonSha256 = new QRadioButton;
    mRadiobuttonSha256->setText(tr("SHA256"));
    mRadiobuttonSha384 = new QRadioButton;
    mRadiobuttonSha384->setText(tr("SHA384"));
    mRadiobuttonSha512 = new QRadioButton;
    mRadiobuttonSha512->setText(tr("SHA512"));
    mRadiobuttonSha512_224 = new QRadioButton;
    mRadiobuttonSha512_224->setText(tr("SHA512-224"));
    mRadiobuttonSha512_256 = new QRadioButton;
    mRadiobuttonSha512_256->setText(tr("SHA512-256"));
    mRadiobuttonSha3_224 = new QRadioButton; ///
    mRadiobuttonSha3_224->setText(tr("SHA3-224"));
    mRadiobuttonSha3_256 = new QRadioButton;
    mRadiobuttonSha3_256->setText(tr("SHA3-256"));
    mRadiobuttonSha3_384 = new QRadioButton;
    mRadiobuttonSha3_384->setText(tr("SHA3-384"));
    mRadiobuttonSha3_512 = new QRadioButton;
    mRadiobuttonSha3_512->setText(tr("SHA3-512"));
    mRadiobuttonShake128 = new QRadioButton;
    mRadiobuttonShake128->setText(tr("SHAKE 128"));
    mRadiobuttonShake256 = new QRadioButton;
    mRadiobuttonShake256->setText(tr("SHAKE 256"));
    mRadiobuttonStreebog256 = new QRadioButton;
    mRadiobuttonStreebog256->setText(tr("GOST R 34.11-2012 256"));
    mRadiobuttonStreebog512 = new QRadioButton;
    mRadiobuttonStreebog512->setText(tr("GOST R 34.11-2012 512"));

    mPushButtonChooseFile = new QPushButton;
    mPushButtonChooseFile->setText(tr("Choose file"));

    QButtonGroup *buttonGroup = new QButtonGroup(this);
    buttonGroup->addButton(mRadioButtonMD4,     0);
    buttonGroup->addButton(mRadioButtonMD5,     1);
    buttonGroup->addButton(mRadioButtonRMD160,  2);
    buttonGroup->addButton(mRadiobuttonSha1,    3);
    buttonGroup->addButton(mRadiobuttonSha224,  4);
    buttonGroup->addButton(mRadiobuttonSha256,  5);
    buttonGroup->addButton(mRadiobuttonSha384,  6);
    buttonGroup->addButton(mRadiobuttonSha512,  7);
    buttonGroup->addButton(mRadiobuttonSha512_224, 8);
    buttonGroup->addButton(mRadiobuttonSha512_256, 9);
    buttonGroup->addButton(mRadiobuttonSha3_224, 10);
    buttonGroup->addButton(mRadiobuttonSha3_256, 11);
    buttonGroup->addButton(mRadiobuttonSha3_384, 12);
    buttonGroup->addButton(mRadiobuttonSha3_512, 13);
    buttonGroup->addButton(mRadiobuttonShake128, 14);
    buttonGroup->addButton(mRadiobuttonShake256, 15);
    buttonGroup->addButton(mRadiobuttonStreebog256, 16);
    buttonGroup->addButton(mRadiobuttonStreebog512, 17);


    QGridLayout *gridLayoutMD = new QGridLayout();
    gridLayoutMD->addWidget(mRadioButtonMD4,        0, 0, 1, 1);
    gridLayoutMD->addWidget(mRadioButtonMD5,        1, 0, 1, 1);
    gridLayoutMD->addWidget(mRadioButtonRMD160,     2, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha1,       3, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha224,     4, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha256,     5, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha384,     6, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha512,     7, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha512_224, 8, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha512_256, 9, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha3_224,   10, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha3_256,   11, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha3_384,   12, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonSha3_512,   13, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonShake128,   14, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonShake256,   15, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonStreebog256, 16, 0, 1, 1);
    gridLayoutMD->addWidget(mRadiobuttonStreebog512, 17, 0, 1, 1);


    gridLayoutMD->addWidget(mPushButtonChooseFile,  18, 1, 1, 1);
    gridLayoutMD->addWidget(mLabelHashResult,       18, 0, 1, 1);
    gridLayoutMD->addWidget(mLabelFileName,         19, 0, 1, 2);
    gridLayoutMD->addWidget(mLineEditResult,        20, 0, 1, 2);
    mGroupBoxDigest->setLayout(gridLayoutMD);

    vBoxLayoutMD->addWidget(mGroupBoxDigest);
    mWidgetDigest->setLayout(vBoxLayoutMD);

    mTabWidget->addTab(mWidgetCipher, tr("Cipher"));

    QThread *kThread = new QThread();
    kObjectMD = new ObjectMessageDigest();
    kObjectMD->moveToThread(kThread);

    connect(kObjectMD, SIGNAL(Finish()), kThread, SLOT(quit()));
    connect(kThread, SIGNAL(finished()), kObjectMD, SLOT(deleteLater()));
    connect(kObjectMD, SIGNAL(Finish()), kObjectMD, SLOT(deleteLater()));
    connect(kObjectMD, &ObjectMessageDigest::SendHashResult, this, &MainWindow::ReceiveHashResult);

    connect(buttonGroup, SIGNAL(buttonClicked(int)), this, SLOT(PushRadioButtonClicked(int)));
    connect(mPushButtonChooseFile, &QPushButton::clicked, this, &MainWindow::PushButtonChooseFile);

    mStateMdAlgo = MD_ALGO::MD_NONE;
    mAlgoName = "NONE";
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::ReceiveHashResult(QByteArray barray)
{
    mLineEditResult->setText(barray.toHex());

    QMessageBox box;
    box.setWindowTitle(tr("Message digest: %1").arg(mAlgoName));
    box.setIcon(QMessageBox::Information);
    box.setText(barray.toHex());
    box.exec();
}

void MainWindow::PushRadioButtonClicked(int id)
{
    switch (id) {
    case 0:
        mStateMdAlgo = MD_ALGO::MD_MD4;
        mAlgoName = "MD4";
        break;

    case 1:
        mStateMdAlgo = MD_ALGO::MD_MD5;
        mAlgoName = "MD5";
        break;

    case 2:
        mStateMdAlgo = MD_ALGO::MD_RMD160;
        mAlgoName = "RIPEMD160";
        break;

    case 3:
        mStateMdAlgo = MD_ALGO::MD_SHA1;
        mAlgoName = "SHA1";
        break;

    case 4:
        mStateMdAlgo = MD_ALGO::MD_SHA224;
        mAlgoName = "SHA224";
        break;

    case 5:
        mStateMdAlgo = MD_ALGO::MD_SHA256;
        mAlgoName = "SHA256";
        break;

    case 6:
        mStateMdAlgo = MD_ALGO::MD_SHA384;
        mAlgoName = "SHA384";
        break;

    case 7:
        mStateMdAlgo = MD_ALGO::MD_SHA512;
        mAlgoName = "SHA512";
        break;

    case 8:
        mStateMdAlgo = MD_ALGO::MD_SHA512_224;
        mAlgoName = "SHA512-224";
        break;

    case 9:
        mStateMdAlgo = MD_ALGO::MD_SHA512_256;
        mAlgoName = "SHA512-256";
        break;

    case 10:
        mStateMdAlgo = MD_ALGO::MD_SHA3_224;
        mAlgoName = "SHA3-224";
        break;

    case 11:
        mStateMdAlgo = MD_ALGO::MD_SHA3_256;
        mAlgoName = "SHA3-256";
        break;

    case 12:
        mStateMdAlgo = MD_ALGO::MD_SHA3_384;
        mAlgoName = "SHA3-384";
        break;

    case 13:
        mStateMdAlgo = MD_ALGO::MD_SHA3_512;
        mAlgoName = "SHA3-512";
        break;

    case 14:
        mStateMdAlgo = MD_ALGO::MD_SHAKE128;
        mAlgoName = "Shake128";
        break;

    case 15:
        mStateMdAlgo = MD_ALGO::MD_SHAKE256;
        mAlgoName = "Shake256";
        break;

    case 16:
        mStateMdAlgo = MD_ALGO::MD_STREEBOG256;
        mAlgoName = "Streebog256";
        break;

    case 17:
        mStateMdAlgo = MD_ALGO::MD_STREEBOG512;
        mAlgoName = "Streebog512";
        break;

    default:
        mStateMdAlgo = MD_ALGO::MD_NONE;
        mAlgoName = "NONE";
        break;
    }
}


void MainWindow::PushButtonChooseFile()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open file for hashing"), QDir::currentPath(), tr("*.*"));
    if (fileName.isEmpty()) {
        QMessageBox box;
        box.setIcon(QMessageBox::Critical);
        box.setText(tr("File not choosed."));
        box.exec();

        return;
    }

    mLabelFileName->setText(fileName);
    kObjectMD->SetMessageDigest(fileName, mStateMdAlgo);
}

