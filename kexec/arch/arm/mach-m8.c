#include <stdint.h>
#include <stdio.h>
#include <libfdt.h>

#include "../../kexec.h"
#include "../../fs2dt.h"
#include "mach.h"

#define INVALID_SOC_REV_ID 0xFFFFFFFF

struct msm_id
{
    uint32_t platform_id;
    uint32_t hardware_id;
    uint32_t soc_rev;
    uint32_t board_rev;
};

static uint32_t m8_dtb_compatible(void *dtb, struct msm_id *devid, struct msm_id *dtb_id)
{
    int root_offset;
    const void *prop;
    int len;

    root_offset = fdt_path_offset(dtb, "/");
    if (root_offset < 0)
    {
        fprintf(stderr, "DTB: Couldn't find root path in dtb!\n");
        return 0;
    }

    prop = fdt_getprop(dtb, root_offset, "qcom,msm-id", &len);
    if (!prop || len <= 0) {
        printf("DTB: qcom,msm-id entry not found\n");
        return 0;
    } else if (len < (int)sizeof(struct msm_id)) {
        printf("DTB: qcom,msm-id entry size mismatch (%d != %d)\n",
            len, sizeof(struct msm_id));
        return 0;
    }

    dtb_id->platform_id = fdt32_to_cpu(((const struct msm_id *)prop)->platform_id);
    dtb_id->hardware_id = fdt32_to_cpu(((const struct msm_id *)prop)->hardware_id);
    dtb_id->soc_rev = fdt32_to_cpu(((const struct msm_id *)prop)->soc_rev);
    dtb_id->board_rev = fdt32_to_cpu(((const struct msm_id *)prop)->board_rev);

    //printf("DTB: found dtb platform %u hw %u soc 0x%x board %u\n",
    //      dtb_id->platform_id, dtb_id->hardware_id, dtb_id->soc_rev, dtb_id->board_rev);

    if (dtb_id->platform_id != devid->platform_id ||
        dtb_id->hardware_id != devid->hardware_id) {
        return 0;
    }

    return 1;
}

static void m8_get_model(char *buf, size_t buf_size)
{
    FILE *f;
    int cnt = 0;

    f = fopen("/proc/device-tree/model", "r");
    if(!f)
    {
        fprintf(stderr, "DTB: Failed to open /proc/device-tree/model!\n");
        return 0;
    }

    cnt = fread(buf, 1, buf_size - 1, f);
    if(cnt >= 0)
        buf[cnt] = 0;

    fclose(f);
}

static int m8_check_model(char *target_model, char *dtb, uint32_t dtb_size)
{
    char *dtb_copy;
    int off;
    char *dtb_model;
    int dtb_model_len = 0;
    int res = 0;

    dtb_copy = xmalloc(dtb_size);
    memcpy(dtb_copy, dtb, dtb_size);

    off = fdt_open_into(dtb_copy, dtb_copy, dtb_size);
    if(off)
    {
        free(dtb_copy);
        die("DTB: fdt_open_into failed %d\n", off);
        return 0;
    }

    dtb_model = fdt_getprop(dtb_copy, 0, "model", &dtb_model_len);
    printf("DTB: found model %.*s\n", dtb_model_len, dtb_model);
    res = strncmp(target_model, dtb_model, dtb_model_len) == 0;
    free(dtb_copy);
    return res;
}

static int m8_choose_dtb(const char *dtb_img, off_t dtb_len, char **dtb_buf, off_t *dtb_length)
{
    char *dtb = (char*)dtb_img;
    char *dtb_end = dtb + dtb_len;
    FILE *f;
    struct msm_id devid, dtb_id;
    char *bestmatch_tag = NULL;
    uint32_t bestmatch_tag_size;
    uint32_t bestmatch_soc_rev_id = INVALID_SOC_REV_ID;
    uint32_t bestmatch_board_rev_id = INVALID_SOC_REV_ID;
    char target_model[64] = { 0 };

    m8_get_model(target_model, sizeof(target_model));

    f = fopen("/proc/device-tree/qcom,msm-id", "r");
    if(!f)
    {
        fprintf(stderr, "DTB: Couldn't open /proc/device-tree/qcom,msm-id!\n");
        free(target_model);
        return 0;
    }

    fread(&devid, sizeof(struct msm_id), 1, f);
    fclose(f);

    devid.platform_id = fdt32_to_cpu(devid.platform_id);
    devid.hardware_id = fdt32_to_cpu(devid.hardware_id);
    devid.soc_rev = fdt32_to_cpu(devid.soc_rev);
    devid.board_rev = fdt32_to_cpu(devid.board_rev);

    printf("DTB: platform %u hw %u soc 0x%x board %u\n",
            devid.platform_id, devid.hardware_id, devid.soc_rev, devid.board_rev);

    while(dtb + sizeof(struct fdt_header) < dtb_end)
    {
        uint32_t dtb_soc_rev_id;
        struct fdt_header dtb_hdr;
        uint32_t dtb_size;

        /* the DTB could be unaligned, so extract the header,
         * and operate on it separately */
        memcpy(&dtb_hdr, dtb, sizeof(struct fdt_header));
        if (fdt_check_header((const void *)&dtb_hdr) != 0 ||
            (dtb + fdt_totalsize((const void *)&dtb_hdr) > dtb_end))
        {
            fprintf(stderr, "DTB: Invalid dtb header!\n");
            break;
        }
        dtb_size = fdt_totalsize(&dtb_hdr);

        if(m8_dtb_compatible(dtb, &devid, &dtb_id))
        {
            if (dtb_id.soc_rev == devid.soc_rev &&
                dtb_id.board_rev == devid.board_rev)
            {
                *dtb_buf = xmalloc(dtb_size);
                memcpy(*dtb_buf, dtb, dtb_size);
                *dtb_length = dtb_size;
                printf("DTB: match 0x%x %u, my id 0x%x %u, len %u\n",
                        dtb_id.soc_rev, dtb_id.board_rev,
                        devid.soc_rev, devid.board_rev, dtb_size);

                if (!target_model[0] || m8_check_model(target_model, dtb, dtb_size))
                    return 1;
            }
            else if(dtb_id.soc_rev <= devid.soc_rev &&
                    dtb_id.board_rev < devid.board_rev)
            {
                if((bestmatch_soc_rev_id == INVALID_SOC_REV_ID) ||
                    (bestmatch_soc_rev_id < dtb_id.soc_rev) ||
                    (bestmatch_soc_rev_id == dtb_id.soc_rev &&
                    bestmatch_board_rev_id < dtb_id.board_rev))
                {
                    bestmatch_tag = dtb;
                    bestmatch_tag_size = dtb_size;
                    bestmatch_soc_rev_id = dtb_id.soc_rev;
                    bestmatch_board_rev_id = dtb_id.board_rev;
                }
            }
        }

        /* goto the next device tree if any */
        dtb += dtb_size;

        // try to skip padding in standalone dtb.img files
        while(dtb < dtb_end && *dtb == 0)
            ++dtb;
    }

    if(bestmatch_tag) {
        printf("DTB: bestmatch 0x%x %u, my id 0x%x %u\n",
                bestmatch_soc_rev_id, bestmatch_board_rev_id,
                devid.soc_rev, devid.board_rev);
        *dtb_buf = xmalloc(bestmatch_tag_size);
        memcpy(*dtb_buf, bestmatch_tag, bestmatch_tag_size);
        *dtb_length = bestmatch_tag_size;
        return 1;
    }

    return 0;
}

static int m8_add_extra_regs(void *dtb_buf)
{
    FILE *f;
    uint32_t reg;
    int res;
    int off;

    off = fdt_path_offset(dtb_buf, "/memory");
    if (off < 0)
    {
        fprintf(stderr, "DTB: Could not find memory node.\n");
        return -1;
    }

    f = fopen("/proc/device-tree/memory/reg", "r");
    if(!f)
    {
        fprintf(stderr, "DTB: Failed to open /proc/device-tree/memory/reg!\n");
        return -1;
    }

    fdt_delprop(dtb_buf, off, "reg");

    while(fread(&reg, sizeof(reg), 1, f) == 1)
        fdt_appendprop(dtb_buf, off, "reg", &reg, sizeof(reg));

    fclose(f);

    if(dtb_add_htc_m8_specific(dtb_buf) < 0)
    {
        fprintf(stderr, "DTB: Failed to add m8 specifics!\n");
        return -1;
    }
    return 0;
}

const char *chosenConfigProps[][6] = { "bootloaderflag", "kernelflag",
            "radioflag", "radioflag_ex2", "debugflag", "radioflag_ex1"};
const char *calibrationProps[][13] = { "als_flash", "bs_flash", "bt_flash",
            "c-sensor", "cam_awb", "g-sensor", "gs_flash", "gyro_flash",
            "p-sensor", "ps_adi_flash", "ps_flash", "wifi_eeprom",
            "ws_flash"};
const char *htc_workaround_reserve_leading_pagesProps[2] = { "compatible",
            "qcom,memblock-reserve"};
int dtb_add_htc_projectid(void *dtb_buf, int off)
{
    FILE *f;
    uint32_t reg;
    int res;

    f = fopen("/proc/device-tree/htc,project-id", "r");
    if(!f)
    {
        fprintf(stderr, "DTB: Failed to open /proc/device-tree/htc,project-id!\n");
        return 0;
    }

    fdt_delprop(dtb_buf, off, "htc,project-id");

    while(fread(&reg, sizeof(reg), 1, f) == 1)
        fdt_appendprop(dtb_buf, off, "htc,project-id", &reg, sizeof(reg));

    fclose(f);
    return 1;
}

int dtb_add_property(void *dtb_buf, int off, char *path, char *property)
{
    FILE *f;
    uint32_t reg;
    int res;

    char proppath[250];
    sprintf(proppath, "/proc/device-tree/%s/%s", path, property);

    f = fopen(proppath, "r");
    if(!f)
    {
        fprintf(stderr, "DTB: Failed to open %s!\n", proppath);
        return 0;
    }

    while(fread(&reg, sizeof(reg), 1, f) == 1)
        fdt_appendprop(dtb_buf, off, property, &reg, sizeof(reg));

    fclose(f);
    return 1;
}

int dtb_add_properties_recursive(void *dtb_buf, int off, char *path, char **properties, int nrprops)
{
    int i, ret;

    for (i = 0; i < nrprops; i++) {
        ret = dtb_add_property(dtb_buf, off, path, properties[i]);
        if (!ret) {
            return ret;
        }
    }
    return 1;
}

int dtb_add_htc_m8_specific(void *dtb_buf)
{
    int ret, off;
    char **configProperties = chosenConfigProps;

    printf("DTB: adding HTC M8 specific\n");

    // calibration_data
    printf("DTB: HTC M8: adding calibration data\n");
    ret = fdt_path_offset(dtb_buf, "/calibration_data");
    if (ret == -FDT_ERR_NOTFOUND) {
        ret = fdt_add_subnode(dtb_buf, 0, "/calibration_data");
    }
    if (ret < 0) {
        fprintf(stderr, "DTB: Error adding /calibration_data node.\n");
        return -1;
    }
    dtb_add_properties_recursive(dtb_buf, ret, "calibration_data", calibrationProps, 13);

    //chosen/config
    printf("DTB: HTC M8: adding chosen/config\n");
    ret = off = fdt_path_offset(dtb_buf, "/chosen");
    if (ret == -FDT_ERR_NOTFOUND) {
        ret = fdt_add_subnode(dtb_buf, ret, "/chosen");
    }

    if (ret < 0) {
        fprintf(stderr, "DTB: Error adding /chosen node.\n");
        return -1;
    }

    ret = fdt_path_offset(dtb_buf, "/chosen/config");
    if (ret == -FDT_ERR_NOTFOUND) {
        ret = fdt_add_subnode(dtb_buf, off, "config");
    }

    if (ret < 0) {
        fprintf(stderr, "DTB: Error adding /chosen/config node.\n");
        return -1;
    }
    dtb_add_properties_recursive(dtb_buf, ret, "chosen/config", configProperties, 6);

    //htc projid
    printf("DTB: HTC M8: adding htc,project-id\n");
    ret = fdt_path_offset(dtb_buf, "/");
    dtb_add_htc_projectid(dtb_buf, ret);

    //htc_workaround_reserve_leading_pages
    printf("DTB: HTC M8: adding htc_workaround_reserve_leading_pages\n");
    ret = fdt_path_offset(dtb_buf, "/htc_workaround_reserve_leading_pages");
    if (ret == -FDT_ERR_NOTFOUND) {
        ret = fdt_add_subnode(dtb_buf, 0, "/htc_workaround_reserve_leading_pages");
    }

    if (ret < 0) {
        fprintf(stderr, "DTB: Error adding /htc_workaround_reserve_leading_pages node.\n");
        return -1;
    }
    dtb_add_properties_recursive(dtb_buf, ret, "htc_workaround_reserve_leading_pages",
        htc_workaround_reserve_leading_pagesProps, 2);

    return 0;
}

char *dtb_get_model()
{
    FILE *f;
    char modelpath[50];
    char *model = (char*)malloc(50);
    int cnt;

    sprintf(modelpath, "/proc/device-tree/model");

    f = fopen(modelpath, "r");
    if(!f)
    {
        fprintf(stderr, "DTB: Failed to open %s!\n", modelpath);
        return 0;
    }

    cnt = fread(model, 1, 50, f);
    model[cnt] = 0;

    fclose(f);

    return model;
}

const struct arm_mach arm_mach_m8 = {
    .boardnames = { "m8", NULL },
    .choose_dtb = m8_choose_dtb,
    .add_extra_regs = m8_add_extra_regs,
};

